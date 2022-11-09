# XELIS Blockchain

XELIS is a blockchain made in Rust and powered by Tokio, using account model with a unique P2p in TCP sending data in raw bytes format directly.
This project is based on an event-driven system combined with the native async/await.
It is possible to create transactions, sign them, and introduce them in a block. A difficulty adjustment algorithm keeps the average block time to 15 seconds.

## Roadmap

- better API: websocket with event on new transaction, and on new block for example.
- Web Socket for new mining jobs: miner get notified only when the block change.
- better CLI daemon
- CLI Wallet
- CLI Miner
- Tx registration based on signature
- BlockDAG
- Support of Smart Contracts (xelis-vm)
- Privacy (through Homomorphic Encryption)

## BlockDAG

XELIS try to implement & use a blockDAG which the rules are the following:
- A block is considered "sync block" when the block height is less than `TOP_HEIGHT - STABLE_HEIGHT_LIMIT` and it's the unique block at a specific height or if it's the heaviest block by cumulative difficulty at its height.
- A block is considered "side block" when block height is less than or equal to height of past 8 topographical blocks.
- A block is considered "orphaned" when the block is not ordered in DAG (no topological height for it).
- A height is not unique anymore.
- Topo height is unique for each block, but can change when the DAG is re-ordered up to `TOP_HEIGHT - STABLE_HEIGHT_LIMIT`.
- You can have up to 3 previous blocks in a block.
- For mining, you have to mine on one of 3 of the most heavier tips.
- Block should not have deviated too much from main chain / heavier tips.
- Maximum 9% of difficulty difference between Tips selected in the same block.

## Storage

|          Tree         | Key Type |    Value Type    |                         Comment                        |
|:---------------------:|:--------:|:----------------:|:------------------------------------------------------:|
|      transactions     |   Hash   |    Transaction   |      Save the whole transaction based on its hash      |
|         blocks        |   Hash   |   Block Header   |      Save the block header only based on its hash      |
|        metadata       |   Hash   |  Block Metadata  | Save the block metadata based on the Block Header hash |
|      topo_by_hash     |   Hash   |      Integer     |       Save a block hash at a specific topo height      |
|      hash_by_topo     |  Integer |       Hash       |      Save a topo height for a specific block hash      |
|    blocks_at_height   |  Integer |   Array of Hash  |        Save all blocks hash at a specific height       |
|         extra         |   Bytes  | No specific type | Actually used to save the highest topo height and TIPS |
| cumulative_difficulty |   Hash   |      Integer     |   Save the cumulative difficulty for each block hash   |

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
- `get_account`
- `count_accounts`
- `count_transactions`
- `submit_transaction`
- `p2p_status`
- `get_mempool`
- `get_tips`
- `is_chain_valid`
- `get_dag_order`

WebSocket allow JSON-RPC call and any app to be notified with `subscribe` method when a specific event happens on the daemon.
Events currently available are:
- `NewBlock`: when a new block is accepted by chain
- `TransactionAddedInMempool`: when a new valid transaction is added in mempool

## XELIS Message

TODO