# XELIS Blockchain

XELIS is a blockchain made in Rust and powered by Tokio, using account model.
It allows deploy custom assets working exactly like the native coin in transactions and wallet.

This project is based on an event-driven system combined with the native async/await and works with a unique and from scratch p2p system.

### Objectives

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

- Expected Block Time is ~`15` seconds
- Address prefix is `xel` on mainnet and `xet` for testnet
- Transaction fee is `0.01000` XEL per KB
- Full coin can be divided up to `5` decimals
- Maximum supply is set at `18.4` millions
- Maximum block size is set at `1.25` MB

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

XELIS try to implement & use a blockDAG which the rules are the following:
- A block is considered `Sync Block` when the block height is less than `TOP_HEIGHT - STABLE_HEIGHT_LIMIT` and it's the unique block at a specific height ~~or if it's the heaviest block by cumulative difficulty at its height~~.
- A block is considered `Side Block` when block height is less than or equal to height of past 8 topographical blocks.
- A block is considered `Orphaned` when the block is not ordered in DAG (no topological height for it).
- A height is not unique anymore.
- Topo height is unique for each block, but can change when the DAG is re-ordered up to `TOP_HEIGHT - STABLE_HEIGHT_LIMIT`.
- You can have up to 3 previous blocks in a block.
- For mining, you have to mine on one of 3 of the most heavier tips.
- Block should not have deviated too much from main chain / heavier tips.
- Maximum 9% of difficulty difference between Tips selected in the same block.
- Side Blocks receive only 30% of block reward.
- Block rewards (with fees) are added to account only when block is in stable height.
- Supply is re-calculated each time the block is re-ordered because its based on topo order.
- Transactions and miner rewards are re-computed when a new block is added and the block there linked to is not yet in stable topo height. 

## Transaction

Transaction types supported:
- Transfer: possibility to send many assets to many addresses in the same TX
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

## P2p

All transfered data are using a custom Serializer/Deserializer made by hand to transform a struct representation in raw bytes directly.
This serialization is done using the fixed position of each fields and their corresponding bits size.

Every data transfered is done through the Packet system which allow easily to read & transfer data and doing the whole serialization itself.

The connection for a new peer (took from the queue or a new incoming connections) is executed through a unique tokio task with the same allocated buffer for handshake. This prevents any DoS attack on creating multiple task and verifying connection.
When the peer is verified and valid, we create him his own tasks. One for reading incoming packets, and another one for writing packets to him.
By separating both directions in two differents task it prevents to block the communication of opposed side.

For transactions propagation, we keep in cache last N transactions sent or received from a peer to not send the same data twice during propagation.

### Handshake

Handshake packet must be the first packet sent with the blockchain state inside when connecting to a peer.
If valid, the peer will send the same packet with is own blockchain state.

Except at beginning, this packet should never be sent again.

### Ping

Ping packet is sent at an regular interval and inform peers of the our blockchain state.
Every 15 minutes, the packet can up to `MAX_LEN` sockets addresses (IPv4 or IPv6) to help others nodes to extends theirs peers list.

### Chain Sync

We select randomly a peer which is higher in height from the peers list than us and send him a chain request.

The chain request includes last `CHAIN_SYNC_REQUEST_MAX_BLOCKS` blocks hashes of our chain with theirs topoheight espaced exponentially.
This data is used by the select peer to try to find a common point with our chain and his own (block hash must be at same topoheight as other peer).
If selected peer found a common point, he add up to `CHAIN_SYNC_RESPONSE_MAX_BLOCKS` blocks hashes ordered by block height.

Through the "ask and await" request object system, we ask the complete block (block header with transactions included) and add it to chain directly.

Chain sync is requested with a minimum interval of `CHAIN_SYNC_DELAY` seconds.

## Storage

All theses data are saved in plaintext.

|          Tree         |  Key Type  |     Value Type    |                          Comment                          |
|:---------------------:|:----------:|:-----------------:|:---------------------------------------------------------:|
|      transactions     |    Hash    |    Transaction    |        Save the whole transaction based on its hash       |
|         blocks        |    Hash    |    Block Header   |        Save the block header only based on its hash       |
|    blocks_at_height   |   Integer  |   Array of Hash   |         Save all blocks hash at a specific height         |
|         extra         |    Bytes   |  No specific type |   Actually used to save the highest topo height and TIPS  |
|      topo_by_hash     |    Hash    |      Integer      |        Save a block hash at a specific topo height        |
|      hash_by_topo     |   Integer  |        Hash       |        Save a topo height for a specific block hash       |
| cumulative_difficulty |    Hash    |      Integer      |     Save the cumulative difficulty for each block hash    |
|         assets        |    Hash    |      No Value     | Used to verify if an assets is well registered and usable |
|         nonces        | Public Key |      Integer      |        Nonce used to prevent replay attacks on TXs        |
|        rewards        |    Hash    |      Integer      |                   Save the block reward                   |
|         supply        |    Hash    |      Integer      |   Calculated supply (past + block reward) at each block   |
|       difficulty      |    Hash    |      Integer      |                 Difficulty for each block                 |
|       tx_blocks       |    Hash    |   Array of Hash   |        All blocks in which this TX hash is included       |
|      assets_hash      | Public Key |      Integer      |    Asset hash with last topoheight of versioned balance   |
|    assets_balances    | Public Key | Versioned Balance |          Tree name is hash of asset + topoheight          |

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
- Values are encrypted using XChaCha20Poly1305 and a random newly generated Nonce each time its saved. 

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
        "notify": "NewBlock"
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
    "method": "subscribe",
    "params": {
        "notify": "NewBlock"
    }
}
```

Events currently available to subscribe are:
- `NewBlock`: when a new block is accepted by chain
- `TransactionAddedInMempool`: when a new valid transaction is added in mempool
- `TransactionExecuted`: when a transaction has been included in a valid block & executed on chain
- `TransactionSCResult`: when a valid TX SC Call hash has been executed by chain
- `NewAsset`: when a new asset has been registered
- `BlockOrdered` when a block is ordered for the first time or reordered to a new topoheight

## XELIS Message

Provide a almost free way to communicate through opened channels on chain between two parties.
The specified receiver can reply for free to any message sent to him as long as the channel paid by the sender is still open.
It can only reply by one message to one message not yet consumed.

This feature would introduce a better way to communicate privately and in a fully decentralized environment with almost no fees.

The channel price is determined by the maximum message size set, and the time it should stay alive (in blocks count).

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

## Dev Fee

No premine, fair-launch, but to fund this project, we set a developer fee percentage at `5%` of every block reward until the project is fully completed.
This will also helps us to rewards community build and attracts others developers.