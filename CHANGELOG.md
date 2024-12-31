# Changelog

This file contains all the changelogs to ensure that changes can be tracked and to provide a summary for interested parties.

To see the full history and exact changes, please refer to the commits history directly.

## v1.16.0

Bug fixes for daemon & wallet, improvements & new features.

Common:
- Base for Smart Contracts
- Ownership / Balance Proofs
- Serializer improvements
- Reorganize files
- Multisig support
- Launch options are now configurable in a JSON config file.

Daemon:
- Several optimizations, bug fixes, rpc methods
- Database "schema" updated, require a full resync
- New P2P Key Exchange system (DH)
- New bootstrap (fast sync) system
- MultiSig support
- Smart Contracts testnet
- Commit Point system to rollback all changes during a deep reorg

Wallet:
- new RPC methods
- MultiSig support
- Detect correct TX version to use
- Fix bugs
- Store the timestamp for each TX (need to resync)
- Breaking changes in API and wallet storage

Misc:
- Add checksum of each precompiled binary in the release

## v1.15.0

Bug fixes for daemon & wallet, improvements & new features.

Common:
- Improve error messges
- non-zero optional serializer fns
- allow nullable responses in RPC client

Daemon:
- fix visual bugs for peerlist
- no connection to tempbanned peers
- `temp_ban_address` cli command
- `print_balance` cli command
- do not include txs present in orphaned tips
- `get_estimated_fee_rates` experimental rpc method

Wallet:
- add `export_transactions` cli command
- more logs

## v1.14.0

Moving to 1.14.0 due to breaking changes in peerlist storage.

Common:
- add new struct for `network_info` rpc method
- clean up in ws json rpc client

Daemon:
- add `get_pruned_topoheight` rpc method
- P2P peerlist is now backed by a DB instead of a traditional JSON file. (Reduce memory usage, and better I/O operations)
-  add `show_peerlist` cli command
- paginate few CLI commands
- don't keep Peer instance in chain sync task, but its priority flag & id only.

Wallet:
- `network_info` rpc method added
- fix `force-stable-balance` CLI option
- add `clear_tx_cache` cli command
- fix blockDAG reorg resync of transactions
- support anonymous browsing for web wallet (no access to directory feature)


## v1.13.4

Bug fixes for nodes with less than 2GB of ram, and for nodes having reorg issues.

All:
- Update CLI description/about text.

Daemon:
- Fix rewind / `pop_blocks` function to:
    - not delete TXs included in more than one block.
    - rewind on sync blocks only
- Reduce Sled cache size from 1 GB to 16 MB to support low devices
- use `--log-level` by default if `--file-log-level` is not provided
- Add option `--internal-cache-size` to config (in bytes) the inner DB cache size
- Add option `--internal-db-mode` to select the DB mode (`slow-space` or `high-throughput`)

## v1.13.3

Bug fixes, add new features, new RPC methods for easier integration including documentation update.

All:
-   updated dependencies
-   file log level is now separated from log-level param

Wallet:
-   workaround support iOS for the web wallet
-   reduce ECDLP L1 to 13 for web wallet
-   filter by asset for list_transactions rpc method
-   show only transfers with expected destination in list_transactions rpc method
-   support optional nonce param for build_transaction rpc method
-   add build_transaction_offline rpc method
-   better check to see if the wallet db exists
-   clear_custom_tree rpc method
-   rework mnemonics for better errors handling
-   prevent double online event to be fired
-   optimize network handler by reducing sync head state calls

Common:
-   new structs used by RPC methods
-   fix resubscribe events during an auto reconnect of the WS client

Daemon:
-   semver requirements for p2p nodes
-   optimize get_account_history for fast search based on filter
-   get_block_template verify now the tips timestamp against current timestamp

Miner:
-   Scratchpad is allocated in heap, not in stack, preventing older devices to crash due to a stack overflow.

## v1.13.2

Several bug fixes

Common:
- support aggregated WS messages (up to 1 MB)
- serializable hard fork configurations
- move max block size constant from daemon to common
- differentiate two errors message with same display text

Daemon:
- add bytes_sent/bytes_recv to p2p rpc results
- add `skip-block-template-txs-verification` launch option to not double check the validity of a TX
- add `swap_blocks_executions_positions` cli command, for debug purposes
- improve `verify_chain` cli command, which will now also check for executed txs and balances/nonces versions.
- add "Block Version" and "POW Algorithm" in `status` cli command
- Fix Chain Validator used to verify the heaviest chain between us and a peer
- Fix chain sync: give correct order of blocks for easier sync
- add `get_hard_forks` rpc method
- don't show transactions unexecuted in account history rpc method
- add `dev_reward` and `miner_reward` in `get_info` rpc method

Miner:
- add `api-bind-address` option to report the stats of the miner in a HTTP response. Thanks to @epsiloong 

Wallet:
- add rpc method clear_tx_cache
- burn, store fee and nonce used
- track highest nonce within burn txs also
- add logout cli command to switch from one wallet to another
- Use indexmap in XSWD permissions to keep order due to signature validity check.
- Display real error of invalid TX with `transfer` cli command.
- Improve `burn` cli command to follow the same format as `transfer`.

## v1.13.1

This minor version is only a fix for daemon:
- stable height not being updated correctly
- p2p tracker on disconnected peer
- missing `algorithm` field in block template result

## v1.13.0

New hard fork version configured:
Expected date: 10/07/2024 12am UTC at block height 434 100.

Common:
- xelis-hash-v2 update
- WASM compatibility
- Add variant "Blob" for extra data to share low overhead data.

Wallet:
- fix missing transactions during scan / rescan
- fix transaction failing
- few bug fixes
- new config parameters to disable blocks scanning, use stable balances only, etc..

Miner:
- support both algorithm and auto switch for hard fork
- internal hasher rework

Daemon:
- Several bug fixes
- add size in RPC Transaction struct
- Increase extra data size from 1 KB to 32 KB per TX.
- Set 1 KB extra data limit size per transfer

## v1.12.0

Wallet:
- Add a new `extra_data` protocol version

Daemon:
- Track block execution order in a new provider (this is also used for chain sync ordering with side blocks)
- Add DAG cancelled transactions in orphaned list.
- add config `--skip-pow-verification` parameter to skip the PoW verification on new blocks.
- lookup host for priority nodes connection, this support the use of a domain name for peers configuration at launch 
- add rpc method  get_transaction_executor
- fix corruption on pop blocks method

Common:
- API changes in prompt read functions

Wallet:
- Network handler: don't skip txs that aren't executed in the block scanned, search the block executor for it
- Rescan: only starting at requested topoheight

## v1.11.0

Misc:
-   rename  `BlockMiner`  to  `BlockWork`
-   fix Block Template explanation

Common:
-   Compatible with journactl (introducting  `--disable-log-color`,  `--disable-interactive-mode`)
-   introduce  `--disable-file-log-date-based`
-   update dependencies
-   add tests on serialization
-   rework JSON RPC Errors

Daemon:
-   Fix mempool: no more ghost TXs stuck
-   few refactoring
-   Use correct channel to terminate p2p tasks
-   prevent any deadlock on TX broadcast
-   add  `split_address`  RPC method

Wallet:
-   Introduce Tx Cache to prevent any front running problem that may happen on high usage
-   Fix estimate fees function

## v1.10.0

Common:
-   support JSON RPC batching requests
-   If no id is set, don't return any response
-   support string id

Daemon:
-   Several bug fixes for chain sync
-   add  `add_peer`  command
-   New P2P Engine
-   New seed nodes (Canada & Great-Britain)
-   add  `miner_reward`  and  `dev_reward`  in block response
-   add  `validate_address`  and  `extract_key_from_address`  RPC methods
-   add  `get_difficulty`  RPC method
-   add  `create_miner_work`  RPC method
-   correct dev fee to 10%

Miner:
-   show node topoheight instead of current job height to prevent misleading

Wallet:
-   fix missing transactions due to DAG reorg

## v1.9.5

Daemon:
-   Hotfix for sync chain: a transaction having a block hash orphaned as reference may cause an error during syncing.

All:
-   Set a specific name for each tokio task in case of debug

## v1.9.4

Daemon:
-   fix fast sync
-   new p2p engine to support more connections, refactor peer/connection struct
-   rename struct BlockMiner to MinerWork
-   add topoheight field in BlockTemplate & MinerWork
-   support MinerWork in SubmitBlockParams to apply the miner job on the node based on a block template.
-   new parameter:  `disable-rpc-server`  to disable the RPC Server
-   rename  `disable-outgoing-connections`  to  `disable-p2p-outgoing-connections`
-   add  `p2p-concurrency-task-count-limit`  to configure the count of parallel tasks for handling incoming connections.
-   Keep track of all accepted blocks from a miner connected to the GetWorkServer.

Miner:
-   support up to 65535 threads
-   Show TopoHeight instead of Height on miner

Wallet:
-   auto reconnect mode

Misc:
-   update README.md
-   update API.md
-   add suport for ARMv7
-   fix certificate not found due to rustls dependency

## v1.9.3

misc:
-   Explain FeeBuilder with variant examples
-   SIMD usage compatible in nightly for xelis-hash

Daemon:
-   add logs
-   few bug fixes (return error to miner on invalid block template)
-   reduce update to every 1s for CLI bottom bar
-   don't temp ban whitelisted/priority peers
-   reduce temp ban for connection error to 1m and increase fail count to 10
-   set new genesis block for testnet, update its genesis hash
-   set a minimum difficulty for devnet/testnet
-   disable http error logs from actix

## v1.9.2

-   Fix invalid fee for tx that can happen when using fast sync or auto pruned mode
-   Add tx hash in logs during pre verify tx.
-   Update dependencies

## v1.9.1

Daemon:
-   add --disable-outgoing-connections to not try to connect to potential outgoing peers.
-   priorize incoming p2p connections using biased in select!
-   auto temp ban on multiple connection failures

Common:
-   fix build on arm due to curve dependency update
-   alignment fix for POW hashing algorithm that can happen on Windows and/or MacOS.

Misc:
-   update README.md
-   improve CI/CD

Wallet:
-   wallet estimate fees take in count registered keys
-   flush wallet storage on creation
-   add transfer_all in CLI wallet

## v1.9.0

XELIS mainnet release

Daemon:
- POW `xelis-hash` algorithm released
- Bug fixes 
- Side blocks reward function updated  
- Registration system through unique fee paid one time.

## v1.8.0

- XELIS HE implementation
- Fully Encrypted P2p Network

Several bug fixes and new RPC methods

## v1.7.0

Common
-   Include short commit hash in version
-   Schnorr Signature implementation with ElGamal keypair
-   improve prompt engine
-   ...

Daemon
-   Fix deadlocks
-   Improve database management
-   rework chain sync system
-   add new commands
-   Bug fixes
-   ...

Wallet
-   Improve XSWD implementation
-   allow a advanced query system for searching/filtering entries in DB
-   add feature to use wallet as a encrypted DB for dApps and other services through RPC & XSWD
-   add new RPC methods
-   Fix bugs
-   ...

## v1.6.0

Common
-   fix prompt bug in Windows
-   ElGamal implementation based on Ristretto255 for homomorphic encryption (not used yet)
-   Improve API, add new events
-   rotating file log based on day (and in logs folder now)
-   fix bug in terminal after a crash
-   ...

Daemon
-   optimize disk usage
-   add new API methods
-   fix errors that could occurs while rewinding chain
-   optimize mempool greatly
-   improve (and fix) fast sync
-   add new events
-   better tx propagation
-   clean up code
-   fix bugs
-   fix block reward emission
-   ...

Wallet
-   improve XSWD protocol
-   disk optimizations
-   new APIs methods
-   Asset standard with decimals precision
-   ...

## v1.5.0

Common
-   Prompt in raw mode for better management of terminal
-   Fix display glitch in terminal

Daemon
-   Better fast sync: can fast sync from any height
-   better synchronization of blockchain
-   add / change RPC methods API
-   rework whole mempool system
-   better block propagation (optimized to reduce network load)
-   fix several bugs
-   several optimizations

Wallet
-   Improve commands system
-   Allow starting wallet without parameters for prompt request mode
-   Implementation of XSWD v1 (this is a safe way for dApp to communicate with any wallet API)
-   Fix bugs and some optimizations

## v1.4.0

-   Fast sync: if enabled when starting the node, no need to synchronize the whole chain history, but only the top blocks.
-   Pruning mode: delete all blocks/transactions/balances before a specific stable topoheight to save lot of storage on disk.
-   P2p Inventory: send mempool txs after syncing the chain
-   keep-alive feature for websockets
-   fix bugs, clean up code

## v1.3.0

-   fix wallet bugs
-   fix miner SSL/TLS bugs
-   improve daemon WebSocket events
-   Change POW form, better performances
-   optimizations in core & p2p
-   full rework of RPC Server part
-   Client protocol
-   Add  `version`  in block header

## v1.2.0

-   Fix chain sync bug
-   One tokio task for all ping interval (optimization)

## v1.1.0

-   Fix overflow bugs
-   improve chain sync
-   split Peer connection in two tasks
-   others fixes / improvements


**NOTE**: Previous versions were not documented correctly, only commits history and small PR for features-specific were created, please see them [here](https://github.com/xelis-project/xelis-blockchain/pulls?q=is%3Apr+is%3Aclosed).