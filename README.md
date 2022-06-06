# XELIS Blockchain

XELIS is a blockchain in Rust (powered by Tokio) using the account model with a unique P2p in TCP sending data in raw bytes format directly. It is possible to create transactions, sign them, and introduce them in a block. A difficulty adjustment algorithm keeps the average block time to 15 seconds.

## Roadmap

- Create a RPC Server for daemon API using Actix
- Web Socket for new mining jobs
- Miner
- Fix bugs
- Wallet
- Smart Contracts support
- Privacy