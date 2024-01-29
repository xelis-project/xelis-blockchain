# XELIS
All rights reserved.

A from scratch blockchain made in Rust and powered by Tokio, using account model. XELIS is based on an event-driven system combined with the native async/await and works with a unique and from scratch p2p system. This allow to be notified on any events happening on the network and to be able to react to them instead of checking periodically for updates.

BlockDAG is enabled to improve the scalability and the security of the network. Homomorphic Encryption using ElGamal is used to provide privacy on transactions (transfered amounts) and balances.

ElGamal cryptosystem was choosen because it's a well known and studied encryption algorithm which has homomorphism features. ElGamal is fast and is used in combination with Ristretto255 curve to provide a good level of security (~128 bits of security). Homomorphic operations available using ElGamal are addition/subtraction between ciphertexts and/or plaintext and multiplication against plaintext value.

Account Model allows to have a more flexible system than UTXO model and to have a better privacy because there is no need to link inputs and outputs, which provide real fungibility. It allows also the fast-sync feature to only download the last state of the blockchain instead of downloading all the history.

Pruning system is also available to reduce the size of the blockchain by removing old blocks and transactions.

We also aims to enabled Smart Contracts support in the future.

We provide differents built-in network:
- Mainnet: Not released yet
- Testnet: Running
- Devnet: this network is used for local development purpose where you want to create your own local chain. It has no peers

## Main features

The main features of XELIS are the following:
- **BlockDAG**: reduce orphaned blocks rate.
- **Egalitarian Mining**: any CPU or GPU can mine XELIS easily.
- **Privacy**: Homomorphic Encryption allows to have encrypted balances and encrypted transfered amounts.
- **Confidential Asset**: Any asset deployed on XELIS network will have the same privacy and functionality like XELIS. Not just a number in a Smart Contract.
- **Event system**: every event happening on the network (daemon or wallet) can be detected and notified easily.
- **Instant Sync**: Your wallet balances and history is synced in few seconds.
- **Smart Contracts**: Create and deploy unstoppable decentralized applications.
- **Integrated addresses**: introduce any data in your wallet address to share informations in a transaction.
- **Easy to use**: We aims to provide the most easiest platform to build and use daily.

## Objectives

The main objectives of XELIS are:
- Provide privacy on transactions / balances.
- Provide Smart Contracts support.
- Secure and fast.

Others objectives in mind are:
- Provide real custom assets working as the native coin.
- Designed as CPU/GPU mining friendly to improve decentralization as possible.
- Simple to use.
- Community driven decisions.

## Config

### Network

- Expected Block Time is `15` seconds
- Address prefix is `xel` on mainnet and `xet` for testnet/devnet
- Transaction fee is `0.01000` XEL per KB
- Up to `8` decimals
- Maximum supply: `18.4` millions
- Maximum block size: `1.25` MB
- Difficulty adjustment algorithm: retarget at every block
- Block reward emission: retarget at every block (Smooth decrease)

### Daemon

- Default P2P port is `2125`
- Defaut RPC Server port is `8080`

### Wallet

- Default RPC Server port is `8081`

## Roadmap

- Include extra fees when sending coins to a not-yet registered address
- Support of Smart Contracts (xelis-vm)
- Privacy (through Homomorphic Encryption)

## BlockDAG

XELIS use a blockDAG with following rules:
- A block is considered `Sync Block` when the block height is less than `TOP_HEIGHT - STABLE_LIMIT` and it's the unique block at a specific height (or only ordered block at its height and don't have lower cumulative difficulty than previous blocks).
- A block is considered `Side Block` when block height is less than or equal to height of past 8 topographical blocks.
- A block is considered `Orphaned` when the block is not ordered in DAG (no topological height for it).
- A height is not unique anymore.
- Topo height is unique for each block, but can change when the DAG is re-ordered up to `TOP_HEIGHT - STABLE_LIMIT`.
- You can have up to 3 previous blocks in a block.
- For mining, you have to mine on one of 3 of the most heavier tips.
- Block should not have deviated too much from main chain / heavier tips.
- Maximum 9% of difficulty difference between Tips selected in the same block.
- Side Blocks receive only 30% of block reward.
- Supply is re-calculated each time the block is re-ordered because its based on topo order.
- Transactions and miner rewards are re-computed when a new block is added and the block there linked to is not yet in stable topo height. 
- A same transaction can be added in more than a block if they are not in the same tip branch. Client protocol will execute it only one time.

Topoheight represents how many unique blocks there is in the blockchain ordered by DAG.

A block ordered is a valid and executed one.

Topoheight order is unstable and may change until the blocks are in the stable height.

Longest chain is the one selected by nodes. But for tips branches conflicts, cumulative difficulty is used to select the main chain.

## Homomorphic Encryption

Homomorphic Encryption (HE) will allow to add privacy on transactions and accounts by doing computation while staying in encrypted form.
Each balances, transaction assets values are in encrypted form and nobody can determine the real value of it except involved parties.

**NOTE**: This part is not yet deployed and is under heavy work.

## Mining

Mining capabilities of XELIS are a bit differents from others chains because of standards being not implemented.
Each job send to a miner is a `BlockMiner` instance in hex format.

The `BlockMiner` is in following format:
- header work hash: 32 bytes
- timestamp (u128 for milliseconds): 16 bytes (BigEndian)
- nonce (u64): 8 bytes (BigEndian)
- extra nonce: 32 bytes
- miner public key: 32 bytes

The total block work size should be equal to 120 bytes.
Header work hash is the immutable part of a block work, its a hash calculated using `Keccak256` hashing algorithm with the following format as input:
- block version: 1 byte
- block height (u64): 8 bytes (BigEndian)
- Hash of the tips: 32 bytes
- Hash of the transactions hashes: 32 bytes

The header work has to be equal to 73 bytes exactly and its hash to 32 bytes.

**NOTE**: Miner key is not included in the immutable of the block work to be have generic block template that can be compatible with any miner. 

All hashes are calculated using the `Keccak256` hashing algorithm except the Proof-Of-Work hash.

POW Hash should be calculated from the `BlockMiner` format and compared against the target difficulty.

NOTE: It is recommended to use the GetWork WebSocket server to be notified of new block work and submit correct work.

Mining jobs are send only when a new block is found or when a new TX is added in mempool.
Miners software are recommended to update themselves the block timestamp (or at least every 500ms) for best network difficulty calculation.

Actually, the POW Hashing algorithm is `Keccak256` which is until we develop (or choose) our own algorithm.

## Client Protocol

XELIS integrate along with BlockDAG a way to accept multiple times the same TX and only execute it one time.
Instead of excluding the whole block because we have a collision with another blockDAG branch for a TX, we just don't execute the TX and keep its hash.

The same TX can be contained in multiple blocks only if:
- TX is not executed in stable height
- TX is not included in block Tips (previous blocks)

Also, for more security, user account should only do TXs on the same chain/tip to prevent any orphaned TX.
An orphaned TX can happens when two differents TXs (but same owner) with the same nonce are sent in two differents branchs. 

During the generation of the DAG order (linking unique topoheight to a block hash), the first block being ordered will execute the TX first.

This feature allows to accept others branch tips even if transactions are the same and prevent more orphans blocks when branches are merged.

## Transaction

Transaction types supported:
- Transfer: possibility to send many assets to many addresses in the same TX (up to 255 outputs inside)
- Burn: publicly burn amount of a specific asset and use this TX as proof of burn (coins are completely deleted from circulation)
- Call Contract: call a Smart Contract with specific parameters and list of assets to deposit (WIP) (NOTE: Multi Call Contract in the same TX ?)
- Deploy Contract: deploy a new (valid) Smart Contract on chain (WIP)

At this moment, transactions are public and have the following data.
|   Field   |       Type      |                                   Comment                                  |
|:---------:|:---------------:|:--------------------------------------------------------------------------:|
|   owner   |    PublicKey    |                         Signer of this transaction                         |
|    data   | TransactionType |                 Type with data included of this transaction                |
|    fee    |     Integer     |             Fees to be paid by the owner for including this TX             |
|   nonce   |     Integer     | Matching nonce of balance to be validated and prevent any replay TX attack |
| signature |    Signature    |          Valid signature to prove that the owner validated this TX         |

Transactions support any registered asset natively.

To prevent any replay attack or double spending, each TX should include a nonce that match the account balance.
After each TX, the nonce is incremented by 1.

## Integrated Address

Integrated address are base address with custom data integrated.
For example, you can integrate in it a unique identifier that will be integrated in the future transaction done using it. Its helpful to determine easily which account to link a transaction with an account/order on service side.

Maximum data allowed is 1KB (same as transaction payload).

Every data is integrated in the transaction payload when using an integrated address.

## P2p

All transfered data are using a custom Serializer/Deserializer made by hand to transform a struct representation in raw bytes directly.
This serialization is done using the fixed position of each fields and their corresponding bits size.

Every data transfered is done through the Packet system which allow easily to read & transfer data and doing the whole serialization itself.

The connection for a new peer (took from the queue or a new incoming connections) is executed through a unique tokio task with the same allocated buffer for handshake. This prevents any DoS attack on creating multiple task and verifying connection.
When the peer is verified and valid, we create him his own tasks. One for reading incoming packets and one for writing packets to him.
By separating both directions in two differents task it prevents blocking the communication of opposed side.

For transactions propagation, we keep in cache last N transactions sent or received from a peer to not send the same data twice during propagation.

The daemon also have 3 tokio tasks running:
- Maintains connections with seed nodes
- Chain sync (which select a random peer for syncing its chain)
- Ping task which build a generic ping packet which is send to every peers connected (or build a specific one for each when its necessary)

### Pruning Mode

This allows anyone who want to run a light node to reduce the blockchain size by deleting blocks, transactions and versioned balances.
The pruned topoheight can only be at a `Sync Block` and behind at least `PRUNE_SAFETY_LIMIT` blocks of the top topoheight.

For wallets connected to a pruned node, you can't retrieve transactions history and miner rewards which happened before the pruned topoheight.
But your balances are still up-to-date with the chain and if your wallets already synced them, they stay in your wallet database.

The security of the chain is not reduced as all your blocks were already verified by your own node locally.

### Fast Sync

Fast sync mode allow you to sync really fast the necessary data only to run a correct and valid version of the chain. For this we request a peer
to send us its chain state at a stable point, which include all accounts nonces, assets, balances, top blocks.
So in future, when the chain will be really heavy, anyone can still join it by using fast sync system, which is compatible with the pruning mode.

**WARNING**: You should use fast sync mode only with a trusted peer, because they can send you a potential fake chain.

### Boost Sync

This is requesting the full chain to others nodes, but faster.
Boost sync mode can be enabled using `--allow-boost-sync-mode`. This mode use more resources but sync much faster.
It is faster because it's requesting blocks to sync in parallel, instead of traditional synchronization that would just request one block, verify it, execute it, repeat.
It's not enabled by default to prevent too much load on nodes. 

This is the perfect mix between Fast sync and traditional chain sync, to have the full ledger while being faster.

### Packets

This parts explains the most importants packets used in XELIS network to communicate over the P2p network.

#### Handshake

Handshake packet must be the first packet sent with the blockchain state inside when connecting to a peer.
If valid, the peer will send the same packet with is own blockchain state.

Except at beginning, this packet should never be sent again.

#### Ping

Ping packet is sent at an regular interval and inform peers of the our blockchain state.
Every 15 minutes, the packet can contains up to `MAX_LEN` sockets addresses (IPv4 or IPv6) to help others nodes to extends theirs peers list.

#### Chain Sync

We select randomly a peer which is higher in height from the peers list than us and send him a chain request.

The chain request includes last `CHAIN_SYNC_REQUEST_MAX_BLOCKS` blocks hashes of our chain with theirs topoheight espaced exponentially.
This data is used by the select peer to try to find a common point with our chain and his own (block hash must be at same topoheight as other peer).
If selected peer found a common point, he add up to `CHAIN_SYNC_RESPONSE_MAX_BLOCKS` blocks hashes ordered by block height.

Through the "ask and await" request object system, we ask the complete block (block header with transactions included) and add it to chain directly.

Chain sync is requested with a minimum interval of `CHAIN_SYNC_DELAY` seconds.

#### Block Propagation

Block propagation packet contains the block header only. Its sent to all peers who have theirs height minus our height less than `STABLE_LIMIT`.
To build the block, we retrieve transactions from mempool.
If a transaction is not found in the mempool, we request it from the same peer in order to build it.

#### Transaction Propagation

Transaction propagation packet contains the hash only to prevent sending the TX.
Its also backed by a cache per peer to knows if the transaction was already received from him / send to him.

## Storage

All theses data are saved in plaintext.

|          Tree         |  Key Type  |     Value Type    |                         Comment                        |
|:---------------------:|:----------:|:-----------------:|:------------------------------------------------------:|
|      transactions     |    Hash    |    Transaction    |      Save the whole transaction based on its hash      |
|         blocks        |    Hash    |    Block Header   |      Save the block header only based on its hash      |
|    blocks_at_height   |   Integer  |   Array of Hash   |        Save all blocks hash at a specific height       |
|         extra         |    Bytes   |  No specific type |Save the highest topo height, pruned topoheight and TIPS|
|      topo_by_hash     |    Hash    |      Integer      |       Save a block hash at a specific topo height      |
|      hash_by_topo     |   Integer  |        Hash       |      Save a topo height for a specific block hash      |
| cumulative_difficulty |    Hash    |      Integer      |   Save the cumulative difficulty for each block hash   |
|         assets        |    Hash    |      Integer      |  Verify if an assets exist and its registration height |
|        rewards        |   Integer  |      Integer      |                  Save the block reward                 |
|         supply        |   Integer  |      Integer      |  Calculated supply (past + block reward) at each block |
|       difficulty      |    Hash    |      Integer      |                Difficulty for each block               |
|       tx_blocks       |    Hash    |   Array of Hash   |      All blocks in which this TX hash is included      |
|       balances        |   Custom   |      Integer      |          Last topoheight of versioned balance          |
|         nonces        | Public Key |      Integer      |     Store the highest topoheight of versioned nonce    |
|  versioned_balances   |   Custom   | Versioned Balance |   Key is composed of topoheight + asset + public key   |
|   versioned_nonces    |   Custom   |  Versioned Nonce  |       Key is composed of topoheight + public key       |

**NOTE**:
- Tree `balances` has a custom key which is composed of 32 bytes of Public Key and 32 bytes of Asset.
- Balances and nonces are versioned, which means they are stored each time a change happened in chain.
- Using a Tree per version is too heavy because of overhead per trees, solution is to hash a generated key based on properties.
- Assets registered have in value their topoheight at which it was registered.
- Supply and block rewards are only stored when the block is topologically ordered

The database engine used is sled. It may changes in future.

Current overhead per block is:
- Tree `blocks` saving Block header (132 bytes with no TXs) value using Hash (32 bytes) key.
- Trees `topo_by_hash` and `hash_by_topo` saving both Hash (32 bytes) <=> topoheight (8 bytes) pointers. (x2)
- Tree `difficulty` saving Difficulty value of a block (8 bytes) using Hash (32 bytes) key.
- Tree `rewards` saving block reward value (8 bytes) using topoheight (8 bytes) key.
- Tree `supply` saving current circulating supply value (8 bytes) using topoheight (8 bytes) key.
- Tree `versioned_balances` is updated at each block (for miner rewards), and also for each account that had interactions (transactions): 72 bytes for key and 16 bytes for value.
- Tree `versioned_nonces` is updated for each account that send at least one TX per topoheight: 40 bytes for key and 16 bytes for value

At this moment with current implementation, minimal overhead per new account is 208 bytes for keys and 56 bytes for values:
- `balances` Public Key + Asset (64 bytes) => topoheight of last versioned balance (8 bytes)
- `nonces` Public Key (32 bytes) => topoheight of last versioned nonce (8 bytes)
- `versioned_balances` Public Topoheight + Key + Asset (72 bytes) => Versioned Balance (16 bytes)
- `versioned_nonces` Topoheight + Public Key (40 bytes) => Versioned Nonce (16 bytes)

An optimized version could be done to reduce further the disk usage by creating pointers.
Instead of saving multiple times the whole Public Key (32 bytes), we create a pointer table to which a u64 value is assigned.
And we store this u64 id instead of the whole Public Key, asset..

## Wallet

Wallet keep tracks of all your transactions on chain, all your assets you own.

When creating a new wallet, it generate a new random secure "master key" which will be encrypted by a password hashed.
This master key allows to change easily the password of your wallet because you only have to save new encrypted version of it.

The master key is also the one which will be able to decrypt/encrypt all your wallet storage.

This way allow to save securely and easily data on any device.

Password hashing algorithm used is Argon2id with a configuration of 15 MB and 16 iterations.

### Storage

Wallet implement a fully-encrypted storage system with following features:
- Tree names are hashed with generated salt
- Keys data are hashed with generated salt
- Values are encrypted using XChaCha20Poly1305 and a random newly generated nonce each time its saved. 

Exception for assets list which has its key encrypted to be able to retrieve them later.

Hash algorithm used is Keccak-256 for keys / tree names.
The random salt generated is a 64 bytes length.
This simple system prevent someone to read / use the data without the necessary secret key.

### Data Type and Value

This protocol allows to transfer data through a custom wallet address called `integrated address`.
It will simply integrate encoded data in the wallet address which can be used to send specific data to the wallet when creating a transaction.
Each transaction can reserve up to 1 KB of space (for encrypted data transfering for example).

You can create simple service / communication on chain through wallets while staying anonymous and in encrypted form.

Actually, you can have following values through API:
- Null value representation
- Boolean
- String
- Unsigned numbers (`u8`, `u16`, `u32`, `u64`, `u128`)

And these types:
- Value (which is only one value, can be used for PaymentID representation)
- Array (of any different values types)
- Fields (which can be used to represent custom `struct` for example)

## API

Http Server run using Actix Framework and serve the JSON-RPC API and WebSocket.

### JSON-RPC

JSON-RPC is available on `/json_rpc` route on RPC server address that you set (or default one).
For a much more detailed API, see the API documentation [here](API.md).

### WebSocket

WebSocket allow JSON-RPC call and any app to be notified when a specific event happens on the daemon.
It is running on `/ws` route on same RPC server address.

Example to subscribe to a registered event in the WebSocket connection:
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

You can notify to several events, just do a request for each event you want.
The daemon will send you every events happening as long as you don't unsubscribe or close the WebSocket.

Example to unsubscribe to a specific event:
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

#### Daemon

Events availables to subscribe on the daemon API are:
- `block_ordered`: when a block is ordered by DAG
- `stable_height_changed`: when the stable height has been updated
- `peer_connected`: when a new peer has connected to the node
- `peer_disconnected`: when a peer disconnected from us
- `peer_peer_list_updated`: when the peerlist of a peer has been updated
- `peer_state_updated`: when the peer state has been updated
- `peer_peer_disconnected`: when a common peer disconnect from one of our peer
- `new_block`: when a new block is accepted by chain
- `transaction_added_in_mempool`: when a new valid transaction is added in mempool
- `transaction_executed`: when a transaction has been included in a valid block & executed on chain
- `transaction_sc_result`: when a valid TX SC Call hash has been executed by chain
- `new_asset`: when a new asset has been registered
- `block_ordered` when a block is ordered for the first time or reordered to a new topoheight
- `block_orphaned` when a block that was previously ordered became orphaned because it was not selected in DAG reorg.

#### Wallet

Events availables to subscribe on the wallet API are:
- `new_topoheight`: when a new topoheight is sent by the daemon
- `new_asset`: when a new asset has been added to the wallet.
- `new_transaction`: when a new transaction (coinbase, outgoing, incoming) has been added to wallet history.
- `balance_changed`: when a balance changes has been detected.
- `rescan`: when a rescan happened on the wallet.
- `online`: when the wallet network state is now online.
- `offline`: whenthe wallet network state is now offline.

### XSWD

XSWD (XELIS Secure WebSocket DApp) Protocol is a WebSocket started on unique port `44325` and path `/xswd` for easy findings from dApps.
Its job is to provide an easy to access and secure way to communicate from a desktop/CLI wallet to any dApp (software or in-browser/websites directly).

It's based on the JSON-RPC API and have exact same methods for easy compabitility, the only exception is how verification is done.
On a traditional RPC-Server, if authentication is enabled, you must provide a username/password.

XSWD stay open but request a manual action from user to accept the connection of the dApp on the XSWD Server.
When accepted, the dApp can requests JSON-RPC methods easily and the user can set/configure a permission for each method.
If no permission is found for a request method, it will be prompted/asked to the user for manual verification.

XSWD also have the ability to sends JSON-RPC requests to the daemon directly.
For this, set the prefix `node.` in front of daemon requests, it will not be requested to the user as it's public on-chain data.
For wallets RPC methods, set the prefix `wallet.` which will requests/use the permission set by the user.

DApp can also request to sign the `ApplicationData` to persist the configured permissions on its side and then provide it when user would reconnect later.

First JSON message from the dApp must be in following format to identify the application:
```json
{
    "id": "0000006b2aec4651b82111816ed599d1b72176c425128c66b2ab945552437dc9",
    "name": "XELIS Example",
    "description": "Description example of up to 255 characters",
    "url": "https://xelis.io",
    "permissions": {}
}
```

You can also add `signature` field and provide signed permissions if your dApp requested a signature from wallet in previous connection.

If dApp is accepted by user through XSWD, you will receive the following response:
```json
{
    "id": null,
    "jsonrpc": "2.0",
    "result": true
}
```

Otherwise, an error like this will be sent and the connection will be closed by the server:
```json
{
    "error": {
        "code": -32603,
        "message": "Invalid JSON format for application data"
    },
    "id": null,
    "jsonrpc": "2.0"
}
```

## How to build

Building this project requires a working [Rust](https://rustup.rs) (stable) toolchain.

It's expected to be cross-platform and guaranteed to work on Linux, Windows, MacOS platforms.

### Build from sub project
Go to one of following folder you want to build from source: `xelis_daemon`, `xelis_miner` or `xelis_wallet`.
To build a release (optimized) version:
`cargo build --release`

### Build from workspace
To build a version from workspace (parent folder) directly, use the option `--bin` with `xelis_daemon`, `xelis_miner` or `xelis_wallet` as value.
Example: `cargo build --release --bin xelis_miner`

You can also build a debug version (just remove `--release` option) or run it directly from cargo:
`cargo run`

### Build from Docker
To build using Docker, use the following command, using the `app` build argument to chose which project to build:
`docker build -t xelis-daemon:master --build-arg app=xelis_daemon .`

## Funding

XELIS is a community driven project and is not funded by any company or organization.
To helps the development, the success and provide a better support of XELIS, we set a dev fee percentage starting at 15% on block reward.

Current dev fee curve is as following:

- 15% from block 0 to 1 250 000 (expected time is ~6 months with side blocks from blockDAG)
- 10% from block 1 250 001 to 3 000 000 (expected time is another ~6 months with side blocks from blockDAG and network growing)
- 5% from 3 000 001 until the project being developed and stable enough to reduce it.
- 