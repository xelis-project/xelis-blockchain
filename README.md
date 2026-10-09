# XELIS

XELIS is the world's first **BlockDAG** with **Privacy**, **Speed**, **Scalability** and **Smart Contracts**.

## Features

- **BlockDAG**: merges parallel mining branches into a topological execution order, reducing orphaned work.
- **Proof of work**: CPU and GPU mining using [xelis-hash](https://github.com/xelis-project/xelis-hash).
- **Difficulty adjustment**: a Gamma rate filter models Poisson block arrivals using observed DAG work and elapsed time. It adapts its smoothing to hashrate changes and limits upward rate changes, then scales the filtered hashrate by the target block time to determine difficulty (previously a Kalman filter was estimating network hashrate from observed DAG work and timestamps, adjusting difficulty for each block).
- **Confidential transactions**: Twisted ElGamal encryption, Pedersen commitments, and zero-knowledge proofs protect transfer amounts and account balances.
- **Smart contracts**: deploy and invoke programs in the sandboxed [xelis-vm](https://github.com/xelis-project/xelis-vm), with persistent storage, asset creation, events, and scheduled execution.
- **Native assets**: registered assets support confidential transfers and encrypted balances.
- **Multisignature accounts**: configure signing thresholds and participants for account transactions.
- **Wallet synchronization**: retrieve balances and transaction history from a daemon without downloading the full blockchain.
- **Pruning and fast sync**: reduce retained history or bootstrap from a trusted peer's chain state.
- **Extra data and blobs**: attach private, public, or proprietary data to transfers, or send data without an asset transfer.
- **Integrated addresses**: embed structured data in an address for payment identification and application integration.
- **Event subscriptions**: receive daemon, wallet, and contract notifications through WebSocket APIs.

See the [documentation](https://docs.xelis.io) for additional guides.

## Networks

The built-in networks are:

- `mainnet`: the production network and the default selection.
- `testnet`: a separate network for testing.
- `devnet`: local development, with no built-in seed nodes. Peers can be configured explicitly, and simulator mode is available.

Select a network with `--network mainnet`, `--network testnet`, or `--network devnet`.

## How to build

Install a [Rust](https://rustup.rs) toolchain and native build tools. The Docker build installs `clang`, `cmake`, and `libclang-dev`; these support the native cryptography and RocksDB dependencies. Native builds also require a C/C++ compiler and the corresponding platform development tools.

The workspace contains three binaries:

| Binary | Purpose |
| --- | --- |
| `xelis_daemon` | Validate and store the blockchain, connect to peers, and serve RPC and mining work |
| `xelis_wallet` | Manage keys, balances, transactions, and dApp permissions |
| `xelis_miner` | Mine blocks through the daemon's GetWork API |

### Build from the workspace

Build all binaries in release mode:

```sh
cargo build --release
```

Build or run a specific binary:

```sh
cargo build --release --bin xelis_daemon
cargo build --release --bin xelis_wallet
cargo build --release --bin xelis_miner
cargo run --release --bin xelis_daemon -- --network devnet
```

Release binaries are written to `target/release/`. Omit `--release` for a debug build.

You can also run `cargo build --release` from `xelis_daemon`, `xelis_wallet`, or `xelis_miner` to build that package.

The daemon enables RocksDB and sled support by default and selects RocksDB as its default backend. Use `--use-db-backend rocksdb`, `--use-db-backend sled`, or `--use-db-backend memory` to select an available backend. The memory backend does not persist data across restarts.

### Build with Docker

Select the binary with the `app` build argument:

```sh
docker build -t xelis-daemon:local --build-arg app=xelis_daemon .
```

Use `app=xelis_wallet` or `app=xelis_miner` for the other binaries. The image runs the selected binary as its entrypoint and uses `/var/run/xelis/data` as its working directory.

## Funding

A share of each block's emission reward is paid to the developer address. The schedule is based on block height:

| Block height | Developer share |
| --- | --- |
| `0` through `3,249,999` | 10% |
| `3,250,000` onward | 5% |

The remaining emission reward goes to the miner. This share applies to the block reward, separately from transaction fees.

## Network parameters

| Parameter | Value |
| --- | --- |
| Target block time | 5 seconds |
| Mainnet address prefix | `xel` |
| Testnet/devnet address prefix | `xet` |
| Native coin precision | 8 decimals; 100,000,000 atomic units per XEL |
| Maximum emission supply | 18,400,000 XEL |
| Maximum block size, including transactions | 1.25 MiB (1,310,720 bytes) |
| Maximum transaction size | 1 MiB (1,048,576 bytes) |
| Maximum parents per block | 3 |
| Stability window | 24 block heights |
| Difficulty adjustment | Every block |
| Emission adjustment | Every ordered block, based on previously emitted supply |

### Transaction fees

The transaction fee combines a size-based base fee, operation costs, and any miner tip:

- The minimum base fee is `0.0001 XEL` per 1,024 bytes, with transaction size rounded up to the next full unit.
- The required base fee rises with a moving average of block size. Its curve is approximately `minimum_base_fee × (1 + 10 × utilization²)`, where utilization is the average block size divided by the maximum block size. Consensus uses fixed-point integer arithmetic.
- Each transfer output adds `0.00005 XEL`.
- Each newly registered destination account adds `0.001 XEL`.
- Each additional multisignature signature adds `0.00005 XEL`.
- Contract deployment requires burning `1 XEL`, in addition to transaction fees and any execution gas.
- Asset creation costs `1 XEL` within contract execution.

The protocol burns 30% of the size-based base fee above its minimum. Contract gas also has a 30% burn share. Use the daemon and wallet fee-estimation APIs to determine fees for a transaction under current network conditions.

### Service addresses

| Service | Address or configuration |
| --- | --- |
| Daemon P2P | `0.0.0.0:2125` by default |
| Daemon RPC and GetWork | `0.0.0.0:8080` by default |
| Wallet daemon connection | `http://127.0.0.1:8080` by default |
| Wallet RPC | Enabled with an explicit `--rpc-bind-address` |
| Wallet XSWD | `127.0.0.1:44325`, path `/xswd` |

## BlockDAG

A block references up to three parent blocks, also called tips. Its height is one greater than the highest parent height, so multiple blocks can share a height.

The DAG uses GHOSTDAG-style merge sets and blue/red classification with an anticone bound of `3`. Cumulative difficulty represents blue work: the selected parent's accumulated work, the block's own work, and the work of additional blue blocks in its merge set. Red blocks do not contribute to this score. Tips are ranked by this score, with deterministic hash ordering to break ties.

An ordered block receives a unique **topoheight**, which identifies its position in the execution order. Topoheight differs from block height. Order can change during a reorganization of the unstable portion of the DAG, requiring affected transactions, rewards, and supply to be recomputed.

- A **sync block** is an ordered block at least 24 heights behind the height being checked, with no other ordered block at its height. Genesis is a sync block.
- A **side block** is an ordered block with another block at the same height ordered before it. Side blocks receive the full emission reward.
- An **orphaned block** has no position in the current topological execution order.
- Additional selected tips must pass the difficulty check against the best tip: their individual difficulty must exceed `floor(best_tip_difficulty × 91 / 100)`.
- Parent selection and block validation also enforce ancestry and distance rules to prevent merging branches that diverge too far from the accepted DAG.

Emission decreases as emitted supply approaches its maximum. In atomic units, the base reward is `(maximum_supply - emitted_supply) >> 20`, scaled by the 5-second target relative to 180 seconds. Burned coins are tracked separately from emitted supply.

## Homomorphic encryption

XELIS uses **Twisted ElGamal** over the Ristretto group, together with Pedersen commitments and Bulletproof range proofs. Homomorphic operations let validators update encrypted balances without learning confidential amounts. Equality and validity proofs establish that the encrypted values and commitments agree.

Confidentiality applies to transfer amounts and account balances. Addresses, transaction structure, fees, public burns, and public contract data remain visible. Native assets use the same confidential transfer mechanisms as XEL.

## Mining

GetWork is available over WebSocket at `/getwork/{address}/{worker}` on the daemon RPC server. Mining jobs contain a hexadecimal `MinerWork` value.

The serialized mining work is **112 bytes**:

| Field | Size | Encoding |
| --- | --- | --- |
| Header work hash | 32 bytes | BLAKE3 digest |
| Timestamp | 8 bytes | Unsigned milliseconds, big-endian |
| Nonce | 8 bytes | Unsigned integer, big-endian |
| Extra nonce | 32 bytes | Raw bytes |
| Miner public key | 32 bytes | Compressed public key |

The header work hash is BLAKE3 over this **73-byte** immutable header work:

| Field | Size |
| --- | --- |
| Block version | 1 byte |
| Block height, big-endian | 8 bytes |
| Tips hash | 32 bytes |
| Transaction hashes digest | 32 bytes |

The tips hash is BLAKE3 over the concatenated parent hashes in header order. The transaction hashes digest is BLAKE3 over the concatenated transaction hashes in header order.

The miner public key is outside the immutable header work hash, allowing the same template to be used for different miners. Pools must verify that submitted shares contain the expected payout public key.

Block and transaction identifiers use BLAKE3. Proof of work uses **xelis-hash** over the 112-byte mining work, and the result must satisfy the target difficulty. Miners should refresh the timestamp while working on a job. New jobs are sent as templates change, subject to the configured GetWork notification rate limit.

## Transaction execution

A transaction can appear in competing DAG branches while executing only once in the accepted topological order. A block cannot repeat transactions already present in its relevant parent history or already executed at the stable point. Duplicate inclusion across independent branches does not require rejecting the entire merged block.

Transactions are checked against the state derived from the block's parents. During topological execution, the daemon checks execution status and account state before applying a transaction. Conflicting transactions from the same account can become orphaned after a reorganization.

Each account has a nonce. A transaction must use the expected nonce, which increments after execution. Transactions also include a block reference used to validate the balance state they were built against.

## Transactions

Supported transaction types are:

- **Transfers**: send registered assets to multiple destinations, with up to 255 outputs.
- **Burn**: publicly burn a nonzero amount of a registered asset.
- **MultiSig**: configure or reset an account's multisignature policy, with up to 255 participants.
- **InvokeContract**: call a contract entry point with parameters, asset deposits, and a gas budget.
- **DeployContract**: deploy validated contract bytecode, optionally invoking its constructor with deposits and gas.
- **Blob**: send opaque data to up to 255 destinations without an asset transfer. A private blob has exactly one destination.

The transaction structure includes:

| Field | Purpose |
| --- | --- |
| `version` | Transaction format |
| `source` | Sender's compressed public key |
| `data` | Transaction type and payload |
| `fee` | Transaction fee, including any tip |
| `fee_limit` | Maximum fee the sender authorizes |
| `nonce` | Account sequence number |
| `source_commitments` | Per-asset source commitments and equality proofs |
| `range_proof` | Aggregated range proof |
| `reference` | Referenced block hash and topoheight |
| `multisig` | Optional additional signatures |
| `signature` | Source signature |

Amounts and fees use atomic units. Contract parameters are limited to 256 KiB, and the maximum gas budget per transaction is 5 XEL.

## Integrated addresses and extra data

An integrated address contains a normal address plus structured data, such as a payment identifier. The wallet incorporates this data into the transfer payload when sending to the address.

- Integrated address data is limited to 1 KiB.
- Each transfer's serialized extra data is limited to 1 KiB, including encoding and encryption overhead.
- The total serialized extra data across a transfer transaction is limited to 32 KiB.
- Blob data is also limited to 32 KiB.

Extra data supports private, public, and proprietary formats. Private data uses separate encryption handles for the sender and receiver, allowing both to decrypt it. Public data is readable on chain; proprietary data follows the application's encoding. Integrated addresses themselves expose their embedded data to anyone who receives the address.

## P2P network

Peers communicate over TCP using custom binary serialization. X25519 Diffie–Hellman establishes a shared secret for exchanging directional encryption keys. Subsequent packets use ChaCha20-Poly1305, with outgoing keys rotated after 1 GiB of encrypted traffic.

The daemon supports cached peer-key verification policies. Packet encryption protects packet contents; peer identity verification depends on the configured key policy.

Read and write tasks handle each peer independently. Per-peer caches track propagated transactions and blocks to avoid redundant announcements. Optional Snappy compression can be enabled with `--enable-p2p-compression` for packets larger than 1 KiB.

### Pruning

Pruning removes old blocks, transactions, and obsolete historical state while retaining the state needed to operate the node. It occurs at a sync block and keeps a safety margin of at least **80 topological blocks**.

Use `--auto-prune-keep-n-blocks <count>` for automatic pruning. A wallet cannot retrieve history or mining rewards older than the daemon's pruning boundary, but current balances remain available and previously synchronized wallet history remains stored locally.

### Synchronization

- **Regular sync**: download and validate blockchain data from peers.
- **Fast sync**: enable with `--allow-fast-sync` to bootstrap from a peer's state at a stable point. This skips local verification of the full historical chain and should use trusted peers.
- **Boost sync**: enable with `--allow-boost-sync` to request blocks in parallel while still validating them locally. This uses more resources to speed up full-chain synchronization.

Fast sync and boost sync cannot be enabled together. Both are disabled by default.

### Packets

- **Key exchange** establishes encryption before the blockchain handshake and also supports key rotation.
- **Handshake** exchanges network identity and blockchain state when establishing a peer connection.
- **Ping** advertises peer state, by default every 10 seconds. Peer address sharing runs at a 5-minute interval and includes up to 16 addresses.
- **Chain sync** requests hashes and topoheights to locate a common chain point, then fetches missing blocks. Requests include up to 64 block identifiers; responses default to 4,096 blocks and are configurable. The minimum request interval per peer is 1 second.
- **Block propagation** announces a header; missing transactions are fetched to reconstruct the block.
- **Transaction propagation** announces transaction hashes, with per-peer caches avoiding repeated announcements.

## Storage

The daemon storage supports RocksDB, sled, or memory as backend.
RocksDB is preferred when both persistent backends are enabled.

Daemon storage does not add encryption at rest. Confidential amounts remain encrypted in the stored transactions and balances; public chain data remains public. Pruning retains a baseline for historical state at the cutoff and rejects rewinds below that boundary.


## Wallet

The wallet manages keys, tracked assets, encrypted balances, transaction history, and pending transactions. It connects to a daemon for chain data and can also operate offline.

A randomly generated master key encrypts wallet storage. The password-derived key encrypts this master key, allowing password changes without re-encrypting the entire database.

Wallets default to **Argon2id with 128 MiB of memory, parallelism 4, and 16 iterations**. Password hashing parameters are stored with the wallet.

Wallet storage uses:

- Salted BLAKE3 hashes for tree names and lookup keys.
- XChaCha20-Poly1305 for values, with a fresh random 24-byte nonce for each encryption.
- A 32-byte storage salt.
- Encrypted keys where their original values must be recoverable, such as asset identifiers.

## API

The daemon and wallet use Actix Web to serve JSON-RPC over HTTP and WebSocket at `/json_rpc`. The wallet RPC server must be explicitly enabled. See [API.md](API.md) and the [API types](xelis_common/src/api) for request and response definitions.

### WebSocket subscriptions

Subscribe to an event with a JSON-RPC request:

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "subscribe",
    "params": {
        "notify": "new_block"
    }
}
```

Use `"method": "unsubscribe"` with the same `notify` value to stop a subscription. A connection can subscribe to multiple events.

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "unsubscribe",
    "params": {
        "notify": "new_block"
    }
}
```

Daemon events include:

- `new_topo_height`, `new_block`, `new_block_template`
- `block_ordered`, `block_orphaned`
- `stable_height_changed`, `stable_topo_height_changed`
- `transaction_added_in_mempool`, `transaction_executed`, `transaction_orphaned`
- `new_asset`, `contract_deploy`
- `peer_connected`, `peer_disconnected`, `peer_peer_list_updated`, `peer_state_updated`, `peer_peer_disconnected`

Contract subscriptions use structured event selectors, for example:

```json
{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "subscribe",
    "params": {
        "notify": {
            "contract_event": {
                "contract": "0000000000000000000000000000000000000000000000000000000000000000",
                "id": null
            }
        }
    }
}
```

Replace the example hash with the deployed contract's hash. `id: null` selects all events from that contract. Other structured selectors are `contract_invoke` with a `contract` hash and `contract_transfers` with an `address`.

Wallet events include:

- `new_topo_height`, `new_asset`, `new_transaction`, `new_pending_transaction`
- `balance_changed`, `rescan`, `history_synced`
- `online`, `offline`, `sync_error`
- `track_asset`, `untrack_asset`

### XSWD

XSWD (XELIS Secure WebSocket DApp) connects applications to the wallet at `ws://127.0.0.1:44325/xswd`. Enable it with `--enable-xswd`; it cannot run alongside the wallet's HTTP RPC server.

Applications register their identity and the wallet RPC methods they intend to use. The user approves the application and controls method permissions. Undeclared wallet methods are rejected. Requests prefixed with `wallet.` use wallet permissions; requests prefixed with `node.` are forwarded to the connected daemon.

An application's first message can be:

```json
{
    "id": "0000006b2aec4651b82111816ed599d1b72176c425128c66b2ab945552437dc9",
    "name": "XELIS Example",
    "description": "Example wallet integration",
    "url": "https://xelis.io",
    "permissions": [
        "get_balance"
    ]
}
```

An accepted registration returns:

```json
{
    "id": "0000006b2aec4651b82111816ed599d1b72176c425128c66b2ab945552437dc9",
    "jsonrpc": "2.0",
    "result": {
        "message": "Application has been registered",
        "success": true
    }
}
```

Invalid or rejected registrations return a JSON-RPC error. See the [XSWD implementation](xelis_wallet/src/api/xswd) for registration validation and permission handling.

