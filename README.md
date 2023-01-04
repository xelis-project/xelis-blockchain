# XELIS Blockchain

XELIS is a blockchain made in Rust and powered by Tokio, using account model.
It allows deploy custom assets working exactly like the native coin in transactions and wallet.

This project is based on an event-driven system combined with the native async/await and works with a unique and from scratch p2p system.

## Objectives

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

- Create a functional wallet (WIP)
- Include extra fees when sending coins to a not-yet registered address
- Web Socket for new mining jobs: miner get notified only when the block change.
- Better CLI daemon
- CLI Wallet
- CLI Miner
- Support of Smart Contracts (xelis-vm)
- Privacy (through Homomorphic Encryption)

## BlockDAG

XELIS try to implement & use a blockDAG which the rules are the following:
- A block is considered `Sync Block` when the block height is less than `TOP_HEIGHT - STABLE_HEIGHT_LIMIT` and it's the unique block at a specific height or if it's the heaviest block by cumulative difficulty at its height.
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

## Storage

|          Tree         |  Key Type  |    Value Type    |                          Comment                          |
|:---------------------:|:----------:|:----------------:|:---------------------------------------------------------:|
|      transactions     |    Hash    |    Transaction   |        Save the whole transaction based on its hash       |
|         blocks        |    Hash    |   Block Header   |        Save the block header only based on its hash       |
|        rewards        |    Hash    |      Integer     |                   Save the block reward                   |
|         assets        |    Hash    |     No Value     | Used to verify if an assets is well registered and usable |
|         nonces        | Public Key |      Integer     |        Nonce used to prevent replay attacks on TXs        |
|         supply        |    Hash    |      Integer     |   Calculated supply (past + block reward) at each block   |
|       difficulty      |    Hash    |      Integer     |                 Difficulty for each block                 |
|      topo_by_hash     |    Hash    |      Integer     |        Save a block hash at a specific topo height        |
|      hash_by_topo     |   Integer  |       Hash       |        Save a topo height for a specific block hash       |
|    blocks_at_height   |   Integer  |   Array of Hash  |         Save all blocks hash at a specific height         |
|         extra         |    Bytes   | No specific type |   Actually used to save the highest topo height and TIPS  |
| cumulative_difficulty |    Hash    |      Integer     |     Save the cumulative difficulty for each block hash    |

## API

Http Server run using Actix Framework and serve the JSON-RPC API and WebSocket.

JSON-RPC methods available:
- `get_height`
- `get_topoheight`
- `get_stableheight`
- `get_block_template`
- `get_block_at_topoheight`
- `get_blocks_at_height`
- `get_block_by_hash`
- `get_top_block`
- `submit_block`
- `get_nonce`
- `get_balance`
- `get_assets`
- `count_transactions`
- `submit_transaction`
- `get_transaction`
- `p2p_status`
- `get_mempool`
- `get_tips`
- `get_dag_order`

WebSocket allow JSON-RPC call and any app to be notified with `subscribe` method when a specific event happens on the daemon.
Events currently available are:
- `NewBlock`: when a new block is accepted by chain
- `TransactionAddedInMempool`: when a new valid transaction is added in mempool

For a much more detailed API, see the API documentation [here](API.md).

## XELIS Message

Provide a almost free way to communicate through opened channels on chain between two parties.
The specified receiver can reply for free to any message sent to him as long as the channel paid by the sender is still open.
It can only reply by one message to one message not yet consumed.

This feature would introduce a better way to communicate privately and in a fully decentralized environment with almost no fees.

The channel price is determined by the maximum message size set, and the time it should stay alive (in blocks count).

## How to build

Building this project requires a working [Rust](https://rustup.rs) (stable) toolchain.

It's expected to be cross-platform and guaranteed to work on Linux, Windows, MacOS platforms.
To build a release (optimized) version:
`cargo build --release --bin daemon`

You can also build a debug version (just remove `--release` option) or run it directly from cargo:
`cargo run --bin daemon`

You can also build `wallet` or `miner` by replacing `daemon` word by it in previous commands.

## Dev Fee

No premine, fair-launch, but to fund this project, we set a developer fee percentage at `5%` of every block reward until the project is fully completed.
This will also helps us to rewards community build and attracts others developers.