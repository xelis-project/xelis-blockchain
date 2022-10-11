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
- A height is not unique anymore.
- Topo height is unique for each block, but can change when the DAG is re-ordered.
- You can have up to 3 previous blocks in a block.
- For mining, you have to mine on one of 3 of the most heavier tips
- Block should not have deviated to much from main chain / heavier tips.

## API

Http Server running using Actix.

Methods available:
- `get_height`
- `get_block_template`
- `get_block_at_height`
- `get_block_by_hash`
- `get_top_block`
- `submit_block`
- `get_account`
- `count_accounts`
- `count_transactions`
- `submit_transaction`
- `p2p_status`
- `get_mempool`
- `is_chain_valid`

## XELIS Message

TODO