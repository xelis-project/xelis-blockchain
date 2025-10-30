use anyhow::Error;
use futures::{stream, TryStreamExt};
use indexmap::IndexSet;
use metrics::{counter, gauge, histogram};
use serde_json::{Value, json};
use xelis_common::{
    api::{
        daemon::{
            BlockOrderedEvent,
            BlockOrphanedEvent,
            BlockType,
            NotifyEvent,
            StableHeightChangedEvent,
            StableTopoHeightChangedEvent,
            TransactionExecutedEvent,
            GetTransactionResult,
            NewContractEvent,
            InvokeContractEvent,
            NewAssetEvent,
            ContractTransfersEvent,
            ContractEvent,
            MempoolTransactionSummary,
        },
        RPCContractLog,
        RPCTransaction,
    },
    asset::{AssetData, VersionedAssetData, MaxSupplyMode, AssetOwner},
    block::{
        Block,
        BlockHeader,
        BlockVersion,
        TopoHeight,
        EXTRA_NONCE_SIZE,
        get_combined_hash_for_tips
    },
    config::{
        COIN_DECIMALS,
        MAXIMUM_SUPPLY,
        MAX_TRANSACTION_SIZE,
        MAX_BLOCK_SIZE,
        TIPS_LIMIT,
        XELIS_ASSET,
        FEE_PER_KB,
        BYTES_PER_KB,
    },
    crypto::{
        Hash,
        Hashable,
        PublicKey,
        pow_hash as compute_pow_hash,
        HASH_SIZE
    },
    difficulty::{
        check_difficulty,
        CumulativeDifficulty,
        Difficulty
    },
    immutable::Immutable,
    network::Network,
    serializer::Serializer,
    time::{
        get_current_time_in_millis,
        TimestampMillis
    },
    transaction::{
        verify::BlockchainVerificationState,
        Transaction,
        TransactionType
    },
    utils::{
        calculate_tx_fee_extra,
        calculate_tx_fee_per_kb,
        format_xelis
    },
    tokio::{
        spawn_task,
        is_multi_threads_supported,
        task::spawn_blocking,
        net::lookup_host,
        sync::{RwLock, Semaphore}
    },
    varuint::VarUint,
    contract::{ModuleMetadata, build_environment},
};
use xelis_vm::Environment;
use crate::{
    config::{
        get_genesis_block_hash, get_hex_genesis_block,
        DEV_FEES, DEV_PUBLIC_KEY, EMISSION_SPEED_FACTOR, GENESIS_BLOCK_DIFFICULTY,
        MILLIS_PER_SECOND, SIDE_BLOCK_REWARD_MAX_BLOCKS, PRUNE_SAFETY_LIMIT,
        SIDE_BLOCK_REWARD_PERCENT, SIDE_BLOCK_REWARD_MIN_PERCENT, STABLE_LIMIT,
        TIMESTAMP_IN_FUTURE_LIMIT, CHAIN_AVERAGE_BLOCK_TIME_N,
    },
    core::{
        config::Config,
        blockdag,
        difficulty,
        error::BlockchainError,
        mempool::Mempool,
        nonce_checker::NonceChecker,
        simulator::Simulator,
        storage::{
            BlockProvider,
            DagOrderProvider,
            DifficultyProvider,
            CacheProvider,
            Storage
        },
        tx_selector::{TxSelector, TxSelectorEntry},
        state::{ChainState, ApplicableChainState},
        hard_fork::*,
        TxCache,
        BlockSizeEma,
    },
    p2p::P2pServer,
    rpc::{
        rpc::{
            get_block_type_for_block,
            get_block_response
        },
        DaemonRpcServer,
        SharedDaemonRpcServer
    }
};
use std::{
    borrow::Cow,
    collections::{
        hash_map::Entry,
        HashMap,
        HashSet,
        VecDeque
    },
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant}
};
use log::{info, error, debug, warn, trace};
use rand::Rng;

use super::storage::{
    AccountProvider,
    BlocksAtHeightProvider,
    ClientProtocolProvider,
    PrunedTopoheightProvider,
};

#[derive(Debug, Clone, Copy)]
pub enum BroadcastOption {
    // P2P + Miners
    All,
    // GetWork
    Miners,
    // None of them
    None,
}

impl BroadcastOption {
    pub fn miners(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn p2p(&self) -> bool {
        matches!(self, Self::All)
    }
}

#[derive(Debug, Clone)]
pub enum PreVerifyBlock {
    Hash(Immutable<Hash>),
    Partial {
        block_hash: Immutable<Hash>,
        pow_hash: Hash
    },
    None,
}

impl PreVerifyBlock {
    pub fn get_block_hash(&self) -> Option<&Hash> {
        match self {
            Self::Hash(v) => Some(v),
            Self::Partial { block_hash, .. } => Some(&block_hash),
            Self::None => None,
        }
    }
}

pub struct Blockchain<S: Storage> {
    // mempool to retrieve/add all txs
    mempool: RwLock<Mempool>,
    // storage to retrieve/add blocks
    storage: RwLock<S>,
    // Current semaphore used to prevent
    // verifying more than one block at a time
    add_block_semaphore: Semaphore,
    // Pre verify N blocks at same time
    // By default, set to N threads available
    pre_verify_block_semaphore: Semaphore,
    // Contract environment stdlib
    environment: Environment<ModuleMetadata>,
    // P2p module
    p2p: RwLock<Option<Arc<P2pServer<S>>>>,
    // RPC module
    rpc: RwLock<Option<SharedDaemonRpcServer<S>>>,
    // if a simulator is set
    simulator: Option<Simulator>,
    // if we should skip PoW verification
    skip_pow_verification: bool,
    // Should we skip block template TXs verification
    skip_block_template_txs_verification: bool,
    // current network type on which one we're using/connected to
    network: Network,
    // auto prune mode if enabled, will delete all blocks every N and keep only N top blocks (topoheight based)
    auto_prune_keep_n_blocks: Option<u64>,
    // Flush storage manually to the disk every N blocks (topoheight based)
    flush_db_every_n_blocks: Option<u64>,
    // Blocks hashes checkpoints expected to be ordered by topoheight
    // No rewind can be done below these blocks
    checkpoints: IndexSet<Hash>,
    // Threads count to use during a block verification
    // If more than one thread is used, it will use batch TXs
    // in differents groups and will verify them in parallel
    // If set to one, it will use the main thread directly
    txs_verification_threads_count: usize,
    // Disable the ZKP Cache
    disable_zkp_cache: bool,
    // Max concurrency allowed for general tasks
    concurrency: usize,
}

impl<S: Storage> Blockchain<S> {
    pub async fn new(mut config: Config, network: Network, storage: S) -> Result<Arc<Self>, Error> {
        // Do some checks on config params
        {
            if config.simulator.is_some() && network != Network::Devnet {
                error!("Impossible to enable simulator mode except in dev network!");
                return Err(BlockchainError::InvalidNetwork.into())
            }
    
            if let Some(keep_only) = config.auto_prune_keep_n_blocks {
                if keep_only < PRUNE_SAFETY_LIMIT {
                    error!("Auto prune mode should keep at least 80 blocks");
                    return Err(BlockchainError::AutoPruneMode.into())
                }
            }

            if config.p2p.allow_boost_sync && config.p2p.allow_fast_sync {
                error!("Boost sync and fast sync can't be enabled at the same time!");
                return Err(BlockchainError::ConfigSyncMode.into())
            }

            if config.skip_pow_verification {
                warn!("PoW verification is disabled! This is dangerous in production!");
            }

            if config.txs_verification_threads_count == 0 {
                error!("TXs threads count must be above 0");
                return Err(BlockchainError::InvalidConfig.into());
            } else {
                info!("Will use {} threads for TXs verification", config.txs_verification_threads_count);
            }

            if config.rpc.threads == 0 {
                error!("RPC threads count must be above 0");
                return Err(BlockchainError::InvalidConfig.into())
            }

            if config.p2p.proxy.kind.is_some() != config.p2p.proxy.address.is_some() {
                error!("P2P Proxy must be specified with an address");
                return Err(BlockchainError::InvalidConfig.into())
            }

            if config.p2p.proxy.username.is_some() != config.p2p.proxy.password.is_some() {
                error!("P2P Proxy auth username/password mismatch");
                return Err(BlockchainError::InvalidConfig.into())
            }

            if config.p2p.max_outgoing_peers > config.p2p.max_peers {
                warn!("max outgoing peers is above max peers, cap it to max peers");
                config.p2p.max_outgoing_peers = config.p2p.max_peers;
            }

            let priority_len = config.p2p.priority_nodes.len();
            if priority_len > config.p2p.max_outgoing_peers {
                warn!("{} priority nodes configured while max outgoing peers is set to {}, increasing max outgoing peers", priority_len, config.p2p.max_outgoing_peers);
                config.p2p.max_outgoing_peers = priority_len;
            }
        }

        let on_disk = storage.has_blocks().await?;
        let environment = build_environment::<S>().build();

        info!("Initializing chain...");
        let blockchain = Self {
            mempool: RwLock::new(Mempool::new(network, config.disable_zkp_cache)),
            storage: RwLock::new(storage),
            add_block_semaphore: Semaphore::new(1),
            pre_verify_block_semaphore: Semaphore::new(config.pre_verify_block_threads_count),
            environment,
            p2p: RwLock::new(None),
            rpc: RwLock::new(None),
            skip_pow_verification: config.skip_pow_verification || config.simulator.is_some(),
            simulator: config.simulator,
            network,
            auto_prune_keep_n_blocks: config.auto_prune_keep_n_blocks,
            skip_block_template_txs_verification: config.skip_block_template_txs_verification,
            checkpoints: config.checkpoints.into_iter().collect(),
            txs_verification_threads_count: config.txs_verification_threads_count,
            flush_db_every_n_blocks: config.flush_db_every_n_blocks,
            disable_zkp_cache: config.disable_zkp_cache,
            concurrency: config.concurrency
        };

        // include genesis block
        if !on_disk {
            blockchain.create_genesis_block(config.genesis_block_hex.as_deref()).await?;
        } else if !config.recovery_mode {
            debug!("Retrieving tips for computing current difficulty");
            let mut storage = blockchain.get_storage().write().await;

            blockchain.initialize_caches(&mut *storage).await?;

            // also do some clean up in case of DB corruption
            if config.check_db_integrity {
                let chain_cache = storage.chain_cache().await;
                let topoheight = chain_cache.topoheight;

                info!("Cleaning data above topoheight {} in case of potential DB corruption", topoheight);
                storage.delete_versioned_data_above_topoheight(topoheight).await?;
            }
        } else {
            warn!("Recovery mode enabled, required pre-computed data have been skipped.");
        }

        let arc = Arc::new(blockchain);
        // create P2P Server
        if !config.p2p.disable {
            let dir_path = config.dir_path;
            let config = config.p2p;
            info!("Starting P2p server...");
            // setup exclusive nodes
            let mut exclusive_nodes: Vec<SocketAddr> = Vec::with_capacity(config.exclusive_nodes.len());
            for peer in config.exclusive_nodes {
                for peer in peer.split(",") {
                    match peer.parse() {
                        Ok(addr) => {
                            exclusive_nodes.push(addr);
                        }
                        Err(e) => {
                            match lookup_host(&peer).await {
                                Ok(it) => {
                                    info!("Valid host found for {}", peer);
                                    for addr in it {
                                        info!("IP from DNS resolution: {}", addr);
                                        exclusive_nodes.push(addr);
                                    }
                                },
                                Err(e2) => {
                                    error!("Error while parsing {} as exclusive node address: {}, {}", peer, e, e2);
                                }
                            };
                            continue;
                        }
                    };
                }
            }

            let proxy_auth = if let (Some(username), Some(password)) = (config.proxy.username, config.proxy.password) {
                Some((username, password))
            } else {
                None
            };

            let proxy = if let (Some(proxy), Some(addr)) = (config.proxy.kind, &config.proxy.address) {
                Some((proxy, addr.parse()?, proxy_auth))
            } else {
                None
            };

            match P2pServer::new(
                config.concurrency_task_count_limit,
                dir_path,
                config.tag,
                config.max_peers,
                config.bind_address,
                Arc::clone(&arc),
                exclusive_nodes,
                config.allow_fast_sync,
                config.allow_boost_sync,
                config.allow_priority_blocks,
                config.max_chain_response_size,
                !config.disable_ip_sharing,
                config.max_outgoing_peers,
                config.dh_private_key.map(|v| v.into()),
                config.on_dh_key_change,
                config.stream_concurrency,
                config.temp_ban_duration.as_secs(),
                config.fail_count_limit,
                config.disable_reexecute_blocks_on_sync,
                config.block_propagation_log_level.into(),
                config.disable_fetching_txs_propagated,
                config.handle_peer_packets_in_dedicated_task,
                config.enable_compression,
                config.disable_fast_sync_support,
                proxy,
            ) {
                Ok(p2p) => {
                    *arc.p2p.write().await = Some(p2p.clone());

                    // connect to priority nodes
                    for addr in config.priority_nodes {
                        for origin in addr.split(",") {
                            let addr: SocketAddr = match origin.parse() {
                                Ok(addr) => addr,
                                Err(e) => {
                                    match lookup_host(&origin).await {
                                        Ok(it) => {
                                            info!("Valid host found for {}", origin);
                                            for addr in it {
                                                info!("Trying to connect to priority node with IP from DNS resolution: {}", addr);
                                                if let Err(e) = p2p.try_to_connect_to_peer(addr, true).await {
                                                    error!("Error while trying to connect to priority node {}: {}", origin, e);
                                                }
                                            }
                                        },
                                        Err(e2) => {
                                            error!("Error while parsing {} as priority node address: {}, {}", origin, e, e2);
                                        }
                                    };
                                    continue;
                                }
                            };
                            info!("Trying to connect to priority node: {}", addr);
                            if let Err(e) = p2p.try_to_connect_to_peer(addr, true).await {
                                error!("Error while trying to connect to priority node {}: {}", addr, e);
                            }
                        }
                    }
                },
                Err(e) => error!("Error while starting P2p server: {}", e)
            };
        }

        // create RPC Server
        if !config.rpc.disable {
            info!("RPC Server will listen on: {}", config.rpc.bind_address);
            match DaemonRpcServer::new(
                Arc::clone(&arc),
                config.rpc
            ).await {
                Ok(server) => *arc.rpc.write().await = Some(server),
                Err(e) => error!("Error while starting RPC server: {}", e)
            };
        }

        // Start the simulator task if necessary
        if let Some(simulator) = arc.simulator {
            warn!("Simulator {} mode enabled!", simulator);
            let blockchain = Arc::clone(&arc);
            spawn_task("simulator", async move {
                simulator.start(blockchain).await;
            });
        }

        Ok(arc)
    }

    pub fn concurrency_limit(&self) -> usize {
        self.concurrency
    }

    // Detect if the simulator task has been started
    pub fn is_simulator_enabled(&self) -> bool {
        self.simulator.is_some()
    }

    // Skip PoW verification flag
    pub fn skip_pow_verification(&self) -> bool {
        self.skip_pow_verification
    }

    // get the environment stdlib for contract execution
    pub fn get_contract_environment(&self) -> &Environment<ModuleMetadata> {
        &self.environment
    }

    // Get the configured threads count for TXS
    pub fn get_txs_verification_threads_count(&self) -> usize {
        self.txs_verification_threads_count
    }

    // Stop all blockchain modules
    // Each module is stopped in its own context
    // So no deadlock occurs in case they are linked
    pub async fn stop(&self) {
        info!("Stopping modules...");
        {
            debug!("stopping p2p module");
            let mut p2p = self.p2p.write().await;
            if let Some(p2p) = p2p.take() {
                p2p.stop().await;
            }
        }

        {
            debug!("stopping rpc module");
            let mut rpc = self.rpc.write().await;
            if let Some(rpc) = rpc.take() {
                rpc.stop().await;
            }
        }

        {
            debug!("stopping storage module");
            let mut storage = self.storage.write().await;
            if let Err(e) = storage.stop().await {
                error!("Error while stopping storage: {}", e);
            }
        }

        {
            debug!("stopping mempool module");
            let mut mempool = self.mempool.write().await;
            mempool.stop().await;
        }

        info!("All modules are now stopped!");
    }

    // Reload the storage and update all cache values
    // Clear the mempool also in case of not being up-to-date
    pub async fn reload_from_disk(&self) -> Result<(), BlockchainError> {
        debug!("Reloading chain from disk");
        let mut storage = self.storage.write().await;
        debug!("storage lock acquired for reload from disk");
        self.reload_from_disk_with_storage(&mut *storage).await
    }

    pub async fn reload_from_disk_with_storage(&self, storage: &mut S) -> Result<(), BlockchainError> {
        debug!("Reloading chain from disk with provided storage");
        self.initialize_caches(storage).await?;
        counter!("xelis_blockchain_reload_from_disk").increment(1);

        // TXs in mempool may be outdated, clear them as they will be asked later again
        {
            debug!("locking mempool for cleaning");
            let mut mempool = self.mempool.write().await;
            debug!("Clearing mempool");

            let chain_cache = storage.chain_cache().await;
            let block_version = get_version_at_height(&self.network, chain_cache.height);
            let tx_base_fee = if block_version >= BlockVersion::V3 {
                self.get_required_base_fee(storage, chain_cache.tips.iter()).await?.0
            } else {
                FEE_PER_KB
            };

            mempool.clean_up(&*storage, &self.environment, chain_cache.stable_topoheight, chain_cache.topoheight, block_version, tx_base_fee, true).await?;
        }

        Ok(())
    }

    async fn initialize_caches(&self, storage: &mut S) -> Result<(), BlockchainError> {
        debug!("Initializing caches from storage");

        let tips = storage.get_tips().await?;
        let (difficulty, _) = self.get_difficulty_at_tips(&*storage, tips.iter()).await?;

        // now compute the stable height
        debug!("Retrieving tips for computing current stable height");
        let (stable_hash, stable_height) = self.find_common_base::<S, _>(&storage, &tips).await?;

        // Search the stable topoheight
        let stable_topoheight = storage.get_topo_height_for_hash(&stable_hash).await?;

        let topoheight = storage.get_top_topoheight().await?;
        let height = storage.get_top_height().await?;

        let chain_cache = storage.chain_cache_mut().await?;

        chain_cache.topoheight = topoheight;
        chain_cache.height = height;
        chain_cache.stable_height = stable_height;
        chain_cache.stable_topoheight = stable_topoheight;
        chain_cache.tips = tips;
        chain_cache.difficulty = difficulty;

        Ok(())
    }

    // function to include the genesis block and register the public dev key.
    async fn create_genesis_block(&self, genesis_hex: Option<&str>) -> Result<(), BlockchainError> {
        debug!("create genesis block");
        let genesis_block = {
            let mut storage = self.storage.write().await;
    
            // register XELIS asset
            debug!("Registering XELIS asset: {} at topoheight 0", XELIS_ASSET);
            let ticker = match self.network {
                Network::Mainnet => "XEL".to_owned(),
                _ => "XET".to_owned(),
            };
    
            storage.add_asset(
                &XELIS_ASSET,
                0,
                VersionedAssetData::new(
                    AssetData::new(COIN_DECIMALS, "XELIS".to_owned(), ticker, MaxSupplyMode::Fixed(MAXIMUM_SUPPLY), AssetOwner::None),
                    None
                )
            ).await?;
    
            let (genesis_block, genesis_hash) = if let Some(genesis_block) = get_hex_genesis_block(&self.network) {
                info!("De-serializing genesis block for network {}...", self.network);
                let genesis = Block::from_hex(genesis_block)?;
                let expected_hash = genesis.hash();
                (genesis, expected_hash)
            } else if let Some(hex) = genesis_hex {
                info!("De-serializing genesis block hex from config...");
                let genesis = Block::from_hex(hex)?;
                let expected_hash = genesis.hash();
    
                (genesis, expected_hash)
            } else {
                warn!("No genesis block found!");
                info!("Generating a new genesis block...");
                let header = BlockHeader::new(BlockVersion::V0, 0, get_current_time_in_millis(), IndexSet::new(), [0u8; EXTRA_NONCE_SIZE], DEV_PUBLIC_KEY.clone(), IndexSet::new());
                let block = Block::new(header, Vec::new());
                let block_hash = block.hash();
                info!("Genesis generated: {} with {:?} {}", block.to_hex(), block_hash, block_hash);
                (block, block_hash)
            };
    
            if *genesis_block.get_miner() != *DEV_PUBLIC_KEY {
                return Err(BlockchainError::GenesisBlockMiner)
            }
    
            if let Some(expected_hash) = get_genesis_block_hash(&self.network) {
                if genesis_hash != *expected_hash {
                    error!("Genesis block hash is invalid! Expected: {}, got: {}", expected_hash, genesis_hash);
                    return Err(BlockchainError::InvalidGenesisHash)
                }
            }
            debug!("Adding genesis block '{}' to chain", genesis_hash);
    
            // hardcode genesis block topoheight
            storage.set_topo_height_for_block(&genesis_hash, 0).await?;
            storage.set_top_height(0).await?;

            genesis_block
        };

        self.add_new_block(genesis_block, PreVerifyBlock::None, BroadcastOption::Miners, false).await?;

        Ok(())
    }

    // mine a block for current difficulty
    // This is for testing purpose and shouldn't be directly used as it will mine on async threads
    // which will reduce performance of the daemon and can take forever if difficulty is high
    pub async fn mine_block(&self, key: &PublicKey) -> Result<Block, BlockchainError> {
        let (mut header, difficulty) = {
            let storage = self.storage.read().await;
            let block = self.get_block_template_for_storage(&storage, key.clone()).await?;
            let (difficulty, _) = self.get_difficulty_at_tips(&*storage, block.get_tips().iter()).await?;
            (block, difficulty)
        };

        let algorithm = get_pow_algorithm_for_version(header.get_version());
        let mut hash = header.get_pow_hash(algorithm)?;
        let mut current_height = self.get_height().await;
        while !self.is_simulator_enabled() && !check_difficulty(&hash, &difficulty)? {
            let height = self.get_height().await;
            if height != current_height {
                current_height = height;
                header = self.get_block_template(key.clone()).await?;
            }
            header.nonce += 1;
            header.timestamp = get_current_time_in_millis();
            hash = header.get_pow_hash(algorithm)?;
        }

        let block = self.build_block_from_header(header).await?;
        let block_height = block.get_height();
        debug!("Mined a new block {} at height {}", hash, block_height);
        Ok(block)
    }

    // Prune the chain until topoheight
    // This will delete all blocks / versioned balances / txs until topoheight in param
    pub async fn prune_until_topoheight(&self, topoheight: TopoHeight) -> Result<TopoHeight, BlockchainError> {
        debug!("prune until topoheight {}", topoheight);
        let mut storage = self.storage.write().await;
        debug!("storage write acquired for pruning");
        self.prune_until_topoheight_for_storage(topoheight, &mut *storage).await
    }

    // delete all blocks / versioned balances / txs until topoheight in param
    // for this, we have to locate the nearest Sync block for DAG under the limit topoheight
    // and then delete all blocks before it
    // keep a marge of PRUNE_SAFETY_LIMIT
    pub async fn prune_until_topoheight_for_storage(&self, topoheight: TopoHeight, storage: &mut S) -> Result<TopoHeight, BlockchainError> {
        if topoheight == 0 {
            return Err(BlockchainError::PruneZero)
        }

        let chain_cache = storage.chain_cache().await;
        let current_topoheight = chain_cache.topoheight;
        let height = chain_cache.height;

        if topoheight >= current_topoheight || current_topoheight - topoheight < PRUNE_SAFETY_LIMIT {
            return Err(BlockchainError::PruneHeightTooHigh)
        }

        // 1 is to not delete the genesis block
        let last_pruned_topoheight = storage.get_pruned_topoheight().await?.unwrap_or(1);
        if topoheight < last_pruned_topoheight {
            return Err(BlockchainError::PruneLowerThanLastPruned)
        }

        // find new stable point based on a sync block under the limit topoheight
        let start = Instant::now();
        let located_sync_topoheight = self.locate_nearest_sync_block_for_topoheight(storage, topoheight, height).await?;
        debug!("Located sync topoheight found {} in {}ms", located_sync_topoheight, start.elapsed().as_millis());

        if located_sync_topoheight > last_pruned_topoheight {
            // delete all blocks until the new topoheight
            let start = Instant::now();
            for topoheight in last_pruned_topoheight..located_sync_topoheight {
                trace!("Pruning block at topoheight {}", topoheight);
                // delete block
                let _ = storage.delete_block_at_topoheight(topoheight).await?;
            }
            debug!("Pruned blocks until topoheight {} in {}ms", located_sync_topoheight, start.elapsed().as_millis());

            let start = Instant::now();
            // delete balances for all assets
            // TODO: this is currently going through ALL data, we need to only detect changes made in last..located
            storage.delete_versioned_data_below_topoheight(located_sync_topoheight, true).await?;
            debug!("Pruned versioned data until topoheight {} in {}ms", located_sync_topoheight, start.elapsed().as_millis());

            // Update the pruned topoheight
            storage.set_pruned_topoheight(Some(located_sync_topoheight)).await?;

            counter!("xelis_blockchain_prune_until_topoheight").increment(1);
            Ok(located_sync_topoheight)
        } else {
            debug!("located_sync_topoheight <= topoheight, no pruning needed");
            Ok(last_pruned_topoheight)
        }
    }

    // determine the topoheight of the nearest sync block until limit topoheight
    pub async fn locate_nearest_sync_block_for_topoheight<P>(&self, provider: &P, mut topoheight: TopoHeight, current_height: u64) -> Result<TopoHeight, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider
    {
        while topoheight > 0 {
            let block_hash = provider.get_hash_at_topo_height(topoheight).await?;
            if self.is_sync_block_at_height(provider, &block_hash, current_height).await? {
                let topoheight = provider.get_topo_height_for_hash(&block_hash).await?;
                return Ok(topoheight)
            }

            topoheight -= 1;
        }

        // genesis block is always a sync block
        Ok(0)
    }

    // returns the highest (unstable) height on the chain
    pub async fn get_height(&self) -> u64 {
        trace!("get height");
        let storage = self.storage.read().await;
        trace!("storage read acquired for get height");

        storage.chain_cache().await
            .height
    }

    // returns the highest topological height
    pub async fn get_topo_height(&self) -> TopoHeight {
        trace!("get topoheight");
        let storage = self.storage.read().await;
        trace!("storage read acquired for get topoheight");

        storage.chain_cache().await
            .topoheight
    }

    // Get the current block height stable
    // No blocks can be added at or below this height
    pub async fn get_stable_height(&self) -> u64 {
        trace!("get stable height");
        let storage = self.storage.read().await;
        trace!("storage read acquired for get stable height");

        storage.chain_cache().await
            .stable_height
    }

    // Get the stable topoheight
    // It is used to determine at which DAG topological height
    // the block is in case of rewind
    pub async fn get_stable_topoheight(&self) -> TopoHeight {
        trace!("get stable topoheight");
        let storage = self.storage.read().await;
        trace!("storage read acquired for get stable topoheight");

        storage.chain_cache().await
            .stable_topoheight
    }

    // Get the network on which this chain is running
    pub fn get_network(&self) -> &Network {
        &self.network
    }

    // Retrieve the cumulative difficulty of the chain
    pub async fn get_cumulative_difficulty(&self) -> Result<CumulativeDifficulty, BlockchainError> {
        debug!("get cumulative difficulty");
        let storage = self.storage.read().await;
        debug!("storage lock acquired for cumulative difficulty");
        let top_block_hash = self.get_top_block_hash_for_storage(&storage).await?;
        storage.get_cumulative_difficulty_for_block_hash(&top_block_hash).await
    }

    // Get the current emitted supply of XELIS at current topoheight
    pub async fn get_supply(&self) -> Result<u64, BlockchainError> {
        debug!("get supply");
        let storage = self.storage.read().await;
        debug!("storage read acquired for get supply");

        let chain_cache = storage.chain_cache().await;
        let topo_height = chain_cache.topoheight;
        storage.get_supply_at_topo_height(topo_height).await
    }

    // Get the count of transactions available in the mempool
    pub async fn get_mempool_size(&self) -> usize {
        trace!("get mempool size");
        self.mempool.read().await.size()
    }

    // Get the current top block hash in chain
    pub async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        debug!("get top block hash");
        let storage = self.storage.read().await;
        debug!("storage read acquired for get top block hash");

        self.get_top_block_hash_for_storage(&storage).await
    }

    // because we are in chain, we already now the highest topoheight
    // we call the get_hash_at_topo_height instead of get_top_block_hash to avoid reading value
    // that we already know
    pub async fn get_top_block_hash_for_storage(&self, storage: &S) -> Result<Hash, BlockchainError> {
        let chain_cache = storage.chain_cache().await;
        let topo_height = chain_cache.topoheight;
        storage.get_hash_at_topo_height(topo_height).await
    }

    // Verify if we have the current block in storage by locking it ourself
    pub async fn has_block(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        debug!("has block {} in chain", hash);
        let storage = self.storage.read().await;
        debug!("storage read acquired for has block {}", hash);
        storage.has_block_with_hash(hash).await
    }

    // Verify if the block is a sync block for current chain height
    pub async fn is_sync_block<P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider + CacheProvider>(&self, provider: &P, hash: &Hash) -> Result<bool, BlockchainError> {
        let chain_cache = provider.chain_cache().await;
        let current_height = chain_cache.height;

        self.is_sync_block_at_height(provider, hash, current_height).await
    }

    // Verify if the block is a sync block
    // A sync block is a block that is ordered and has the highest cumulative difficulty at its height
    // It is used to determine if the block is a stable block or not
    async fn is_sync_block_at_height<P>(&self, provider: &P, hash: &Hash, height: u64) -> Result<bool, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider
    {
        trace!("is sync block {} at height {}", hash, height);
        let block_height = provider.get_height_for_block_hash(hash).await?;
        if block_height == 0 { // genesis block is a sync block
            trace!("Block {} at height {} is a sync block because it can only be the genesis block", hash, block_height);
            return Ok(true)
        }

        // block must be ordered and in stable height
        if block_height + STABLE_LIMIT > height || !provider.is_block_topological_ordered(hash).await? {
            trace!("Block {} at height {} is not a sync block, it is not in stable height", hash, block_height);
            return Ok(false)
        }

        // We are only pruning at sync block
        if let Some(pruned_topo) = provider.get_pruned_topoheight().await? {
            let topoheight = provider.get_topo_height_for_hash(hash).await?;
            if pruned_topo == topoheight {
                // We only prune at sync block, if block is pruned, it is a sync block
                trace!("Block {} at height {} is a sync block, it is pruned", hash, block_height);
                return Ok(true)
            }
        }

        // if block is alone at its height, it is a sync block
        let tips_at_height = provider.get_blocks_at_height(block_height).await?;
        // This may be an issue with orphaned blocks, we can't rely on this
        // if tips_at_height.len() == 1 {
        //     return Ok(true)
        // }

        // if block is not alone at its height and they are ordered (not orphaned), it can't be a sync block
        for hash_at_height in tips_at_height {
            if *hash != hash_at_height && provider.is_block_topological_ordered(&hash_at_height).await? {
                trace!("Block {} at height {} is not a sync block, it has more than 1 block at its height", hash, block_height);
                return Ok(false)
            }
        }

        // now lets check all blocks until STABLE_LIMIT height before the block
        let stable_point = if block_height >= STABLE_LIMIT {
            block_height - STABLE_LIMIT
        } else {
            STABLE_LIMIT - block_height
        };
        let mut i = block_height - 1;
        let mut pre_blocks = HashSet::new();
        while i >= stable_point && i != 0 {
            let blocks = provider.get_blocks_at_height(i).await?;
            pre_blocks.extend(blocks);
            i -= 1;
        }

        let sync_block_cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(hash).await?;
        // if potential sync block has lower cumulative difficulty than one of past blocks, it is not a sync block
        for pre_hash in pre_blocks {
            // We compare only against block ordered otherwise we can have desync between node which could lead to fork
            // This is rare event but can happen
            if provider.is_block_topological_ordered(&pre_hash).await? {
                let cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(&pre_hash).await?;
                if cumulative_difficulty >= sync_block_cumulative_difficulty {
                    debug!("Block {} at height {} is not a sync block, it has lower cumulative difficulty than block {} at height {}", hash, block_height, pre_hash, i);
                    return Ok(false)
                }
            }
        }

        trace!("block {} at height {} is a sync block", hash, block_height);

        Ok(true)
    }

    async fn find_tip_base<P>(&self, provider: &P, hash: &Hash, height: u64, pruned_topoheight: TopoHeight) -> Result<(Hash, u64), BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider + CacheProvider
    {
        debug!("find tip base for {} at height {}", hash, height);
        let chain_cache = provider.chain_cache().await;

        debug!("accessing tip base cache for {} at height {}", hash, height);
        let mut cache = chain_cache.tip_base_cache.lock().await;
        debug!("tip base cache locked for {} at height {}", hash, height);

        let mut stack: VecDeque<Hash> = VecDeque::new();
        stack.push_back(hash.clone());

        let mut bases: IndexSet<(Hash, u64)> = IndexSet::new();
        let mut processed = HashSet::new();

        'main: while let Some(current_hash) = stack.pop_back() {
            trace!("Finding tip base for {} at height {}", current_hash, height);
            processed.insert(current_hash.clone());
            if pruned_topoheight > 0 && provider.is_block_topological_ordered(&current_hash).await? {
                let topoheight = provider.get_topo_height_for_hash(&current_hash).await?;
                // Node is pruned, we only prune chain to stable height / sync block so we can return the hash
                if topoheight <= pruned_topoheight {
                    let block_height = provider.get_height_for_block_hash(&current_hash).await?;
                    debug!("Node is pruned, returns tip {} at {} as stable tip base", current_hash, block_height);
                    bases.insert((current_hash.clone(), block_height));
                    continue 'main;
                }
            }

            // first, check if we have it in cache
            if let Some((base_hash, base_height)) = cache.get(&(current_hash.clone(), height)) {
                trace!("Tip Base for {} at height {} found in cache: {} for height {}", current_hash, height, base_hash, base_height);
                bases.insert((base_hash.clone(), *base_height));
                continue 'main;
            }

            let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
            let tips_count = tips.len();
            if tips_count == 0 { // only genesis block can have 0 tips saved
                // save in cache
                cache.put((hash.clone(), height), (current_hash.clone(), height));
                bases.insert((current_hash.clone(), 0));
                continue 'main;
            }

            for tip_hash in tips.iter() {
                if pruned_topoheight > 0 && provider.is_block_topological_ordered(&tip_hash).await? {
                    let topoheight = provider.get_topo_height_for_hash(&tip_hash).await?;
                    // Node is pruned, we only prune chain to stable height / sync block so we can return the hash
                    if topoheight <= pruned_topoheight {
                        let block_height = provider.get_height_for_block_hash(&tip_hash).await?;
                        debug!("Node is pruned, returns tip {} at {} as stable tip base", tip_hash, block_height);
                        bases.insert((tip_hash.clone(), block_height));
                        continue 'main;
                    }
                }

                // if block is sync, it is a tip base
                if self.is_sync_block_at_height(provider, &tip_hash, height).await? {
                    let block_height = provider.get_height_for_block_hash(&tip_hash).await?;
                    // save in cache
                    cache.put((hash.clone(), height), (tip_hash.clone(), block_height));
                    bases.insert((tip_hash.clone(), block_height));
                    continue 'main;
                }

                if !processed.contains(tip_hash) {
                    // Tip was not sync, we need to find its tip base too
                    stack.push_back(tip_hash.clone());
                }
            }
        }

        if bases.is_empty() {
            error!("Tip base for {} at height {} not found", hash, height);
            return Err(BlockchainError::ExpectedTips)
        }

        // now we sort descending by height and return the last element deleted
        bases.sort_by(|(_, a), (_, b)| b.cmp(a));
        debug_assert!(bases[0].1 >= bases[bases.len() - 1].1);

        let (base_hash, base_height) = bases.pop().ok_or(BlockchainError::ExpectedTips)?;

        // save in cache
        cache.put((hash.clone(), height), (base_hash.clone(), base_height));
        trace!("Tip Base for {} at height {} found: {} for height {}", hash, height, base_hash, base_height);

        Ok((base_hash, base_height))
    }

    // find the common base (block hash and block height) of all tips
    pub async fn find_common_base<'a, P, I>(&self, provider: &P, tips: I) -> Result<(Hash, u64), BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider + CacheProvider,
        I: IntoIterator<Item = &'a Hash> + Copy,
    {
        debug!("find common base for tips {}", tips.into_iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "));
        let chain_cache = provider.chain_cache().await;

        debug!("accessing common base cache");
        let mut cache = chain_cache.common_base_cache.lock().await;
        debug!("common base cache locked");

        let combined_tips = get_combined_hash_for_tips(tips.into_iter());
        if let Some((hash, height)) = cache.get(&combined_tips) {
            debug!("Common base found in cache: {} at height {}", hash, height);
            return Ok((hash.clone(), *height))
        }

        let mut best_height = 0;
        // first, we check the best (highest) height of all tips
        for hash in tips.into_iter() {
            let height = provider.get_height_for_block_hash(hash).await?;
            if height > best_height {
                best_height = height;
            }
        }

        let pruned_topoheight = provider.get_pruned_topoheight().await?.unwrap_or(0);
        let mut bases = Vec::new();
        for hash in tips.into_iter() {
            trace!("Searching tip base for {}", hash);
            bases.push(self.find_tip_base(provider, hash, best_height, pruned_topoheight).await?);
        }

        // check that we have at least one value
        if bases.is_empty() {
            error!("bases list is empty");
            return Err(BlockchainError::ExpectedTips)
        }

        // sort it descending by height
        // a = 5, b = 6, b.cmp(a) -> Ordering::Greater
        bases.sort_by(|(_, a), (_, b)| b.cmp(a));
        debug_assert!(bases[0].1 >= bases[bases.len() - 1].1);

        // retrieve the first block hash with its height
        // we delete the last element because we sorted it descending
        // and we want the lowest height
        let (base_hash, base_height) = bases.remove(bases.len() - 1);
        debug!("Common base {} with height {} on {}", base_hash, base_height, bases.len() + 1);

        // save in cache
        cache.put(combined_tips, (base_hash.clone(), base_height));

        Ok((base_hash, base_height))
    }

    async fn build_reachability<P: DifficultyProvider>(&self, provider: &P, hash: Hash) -> Result<HashSet<Hash>, BlockchainError> {
        let mut set = HashSet::new();
        let mut stack: VecDeque<(Hash, u64)> = VecDeque::new();
        stack.push_back((hash, 0));
    
        while let Some((current_hash, current_level)) = stack.pop_back() {
            if current_level >= 2 * STABLE_LIMIT {
                trace!("Level limit reached, adding {}", current_hash);
                set.insert(current_hash);
            } else {
                trace!("Level {} reached with hash {}", current_level, current_hash);
                let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
                set.insert(current_hash);
                for past_hash in tips.iter() {
                    if !set.contains(past_hash) {
                        stack.push_back((past_hash.clone(), current_level + 1));
                    }
                }
            }
        }

        Ok(set)
    }

    // this function check that a TIP cannot be refered as past block in another TIP
    async fn verify_non_reachability<P: DifficultyProvider>(&self, provider: &P, tips: &IndexSet<Hash>) -> Result<bool, BlockchainError> {
        trace!("Verifying non reachability for block");
        let tips_count = tips.len();
        let mut reach = Vec::with_capacity(tips_count);
        for hash in tips {
            let set = self.build_reachability(provider, hash.clone()).await?;
            reach.push(set);
        }

        for i in 0..tips_count {
            for j in 0..tips_count {
                // if a tip can be referenced as another's past block, its not a tip
                if i != j && reach[j].contains(&tips[i]) {
                    debug!("Tip {} (index {}) is reachable from tip {} (index {})", tips[i], i, tips[j], j);
                    trace!("reach: {}", reach[j].iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", "));
                    return Ok(false)
                }
            }
        }
        Ok(true)
    }

    // Search the lowest height available from the tips of a block hash
    // We go through all tips and their tips until we have no unordered block left
    async fn find_lowest_height_from_mainchain<P>(&self, provider: &P, hash: Hash) -> Result<Option<u64>, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        // Lowest height found from mainchain
        let mut lowest_height = None;
        // Current stack of blocks to process
        let mut stack: VecDeque<Hash> = VecDeque::new();
        // Because several blocks can have the same tips,
        // prevent to process a block twice
        let mut processed = HashSet::new();

        stack.push_back(hash);

        while let Some(current_hash) = stack.pop_back() {
            if processed.contains(&current_hash) {
                continue;
            }

            let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;
            for tip_hash in tips.iter() {
                if provider.is_block_topological_ordered(tip_hash).await? {
                    let height = provider.get_height_for_block_hash(tip_hash).await?;
                    if lowest_height.is_none_or(|h| h > height) {
                        lowest_height = Some(height);
                    }
                } else {
                    stack.push_back(tip_hash.clone());
                }
            }
            processed.insert(current_hash);
        }

        Ok(lowest_height)
    }

    // Search the lowest height available from this block hash
    // This function is used to calculate the distance from mainchain
    // It will recursively search all tips and their height
    // If a tip is not ordered, we will search its tips until we find an ordered block
    async fn calculate_distance_from_mainchain<P>(&self, provider: &P, hash: &Hash) -> Result<Option<u64>, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        if provider.is_block_topological_ordered(hash).await? {
            let height = provider.get_height_for_block_hash(hash).await?;
            debug!("calculate_distance: Block {} is at height {}", hash, height);
            return Ok(Some(height))
        }
        debug!("calculate_distance: Block {} is not ordered, calculate distance from mainchain", hash);
        let lowest_height = self.find_lowest_height_from_mainchain(provider, hash.clone()).await?;

        debug!("calculate_distance: lowest height found is {:?}", lowest_height);
        Ok(lowest_height)
    }

    // Verify if the block is not too far from mainchain
    // We calculate the distance from mainchain and compare it to the height
    async fn is_near_enough_from_main_chain<P>(&self, provider: &P, hash: &Hash, chain_height: u64) -> Result<bool, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        let Some(lowest_ordered_height) = self.calculate_distance_from_mainchain(provider, hash).await? else {
            return Ok(false);
        };

        debug!("distance for block {}: {} at chain height {}", hash, lowest_ordered_height, chain_height);

        // If the lowest ordered height is below or equal to current chain height
        // and that we have a difference bigger than our stable limit
        if lowest_ordered_height <= chain_height && chain_height - lowest_ordered_height >= STABLE_LIMIT {
            return Ok(false)
        }

        Ok(true)
    }

    // Find tip work score internal for a block hash
    // this will recursively find all tips and their difficulty
    async fn find_tip_work_score_internal<'a, P>(&self, provider: &P, map: &mut HashMap<Hash, CumulativeDifficulty>, hash: &'a Hash, base_topoheight: TopoHeight) -> Result<(), BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        trace!("Finding tip work score for {}", hash);

        let mut stack: VecDeque<Hash> = VecDeque::new();
        stack.push_back(hash.clone());

        while let Some(current_hash) = stack.pop_back() {
            let tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;

            for tip_hash in tips.iter() {
                if !map.contains_key(tip_hash) {
                    let is_ordered = provider.is_block_topological_ordered(tip_hash).await?;
                    if !is_ordered || (is_ordered && provider.get_topo_height_for_hash(tip_hash).await? >= base_topoheight) {
                        stack.push_back(tip_hash.clone());
                    }
                }
            }

            if !map.contains_key(&current_hash) {
                map.insert(current_hash.clone(), provider.get_difficulty_for_block_hash(&current_hash).await?.into());
            }
        }
    
        Ok(())
    }

    // find the sum of work done
    pub async fn find_tip_work_score<P>(
        &self,
        provider: &P,
        block_hash: &Hash,
        block_tips: impl Iterator<Item = &Hash>,
        block_difficulty: Option<Difficulty>,
        base_block: &Hash,
        base_block_height: u64
    ) -> Result<(HashSet<Hash>, CumulativeDifficulty), BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + CacheProvider
    {
        trace!("find tip work score for {} at base {}", block_hash, base_block);
        let chain_cache = provider.chain_cache().await;

        debug!("accessing tip work score cache for {} at height {}", block_hash, base_block_height);
        let mut cache = chain_cache.tip_work_score_cache.lock().await;
        if let Some(value) = cache.get(&(block_hash.clone(), base_block.clone(), base_block_height)) {
            trace!("Found tip work score in cache: set [{}], height: {}", value.0.iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "), value.1);
            return Ok(value.clone())
        }

        let mut map: HashMap<Hash, CumulativeDifficulty> = HashMap::new();
        let block_difficulty = if let Some(diff) = block_difficulty {
            diff
        } else {
            provider.get_difficulty_for_block_hash(&block_hash).await?
        };

        map.insert(block_hash.clone(), block_difficulty);

        let base_topoheight = provider.get_topo_height_for_hash(base_block).await?;
        for hash in block_tips {
            if !map.contains_key(hash) {
                let is_ordered = provider.is_block_topological_ordered(hash).await?;
                if !is_ordered || (is_ordered && provider.get_topo_height_for_hash(hash).await? >= base_topoheight) {
                    self.find_tip_work_score_internal(provider, &mut map, hash, base_topoheight).await?;
                }
            }
        }

        if base_block != block_hash {
            map.insert(base_block.clone(), provider.get_cumulative_difficulty_for_block_hash(base_block).await?);
        }

        let mut set = HashSet::with_capacity(map.len());
        let mut score = CumulativeDifficulty::zero();
        for (hash, value) in map {
            set.insert(hash);
            score += value;
        }

        // save this result in cache
        cache.put((block_hash.clone(), base_block.clone(), base_block_height), (set.clone(), score));

        Ok((set, score))
    }

    // find the best tip (highest cumulative difficulty)
    // We get their cumulative difficulty and sort them then take the first one
    async fn find_best_tip<'a, P: DifficultyProvider + DagOrderProvider + CacheProvider>(&self, provider: &P, tips: &'a HashSet<Hash>, base: &Hash, base_height: u64) -> Result<&'a Hash, BlockchainError> {
        if tips.len() == 0 {
            return Err(BlockchainError::ExpectedTips)
        }

        let mut scores = Vec::with_capacity(tips.len());
        for hash in tips {
            let block_tips = provider.get_past_blocks_for_block_hash(hash).await?;
            let (_, cumulative_difficulty) = self.find_tip_work_score(provider, hash, block_tips.iter(), None, base, base_height).await?;
            scores.push((hash, cumulative_difficulty));
        }

        blockdag::sort_descending_by_cumulative_difficulty(&mut scores);
        let (best_tip, _) = scores[0];
        Ok(best_tip)
    }

    // this function generate a DAG paritial order into a full order using recursive calls.
    // hash represents the best tip (biggest cumulative difficulty)
    // base represents the block hash of a block already ordered and in stable height
    // the full order is re generated each time a new block is added based on new TIPS
    // first hash in order is the base hash
    // base_height is only used for the cache key
    async fn generate_full_order<P>(&self, provider: &P, hash: &Hash, base: &Hash, base_height: u64, base_topo_height: TopoHeight) -> Result<IndexSet<Hash>, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + CacheProvider
    {
        trace!("generate full order for {} with base {}", hash, base);

        let chain_cache = provider.chain_cache().await;
        debug!("accessing full order cache for {} with base {}", hash, base);
        let mut cache = chain_cache.full_order_cache.lock().await;

        // Full order that is generated
        let mut full_order = IndexSet::new();
        // Current stack of hashes that need to be processed
        let mut stack: VecDeque<Hash> = VecDeque::new();
        stack.push_back(hash.clone());

        // Keep track of processed hashes that got reinjected for correct order
        let mut processed = IndexSet::new();

        'main: while let Some(current_hash) = stack.pop_back() {
            // If it is processed and got reinjected, its to maintains right order
            // We just need to insert current hash as it the "final hash" that got processed
            // after all tips
            if processed.contains(&current_hash) {
                full_order.insert(current_hash);
                continue 'main;
            }

            // Search in the cache to retrieve faster the full order
            let cache_key = (current_hash.clone(), base.clone(), base_height);
            if let Some(order_cache) = cache.get(&cache_key) {
                full_order.extend(order_cache.clone());
                continue 'main;
            }

            // Retrieve block tips
            let block_tips = provider.get_past_blocks_for_block_hash(&current_hash).await?;

            // if the block is genesis or its the base block, we can add it to the full order
            if block_tips.is_empty() || current_hash == *base {
                let mut order = IndexSet::new();
                order.insert(current_hash.clone());
                cache.put(cache_key, order.clone());
                full_order.extend(order);
                continue 'main;
            }

            // Calculate the score for each tips above the base topoheight
            let mut scores = Vec::new();
            for tip_hash in block_tips.iter() {
                let is_ordered = provider.is_block_topological_ordered(tip_hash).await?;
                if !is_ordered || (is_ordered && provider.get_topo_height_for_hash(tip_hash).await? >= base_topo_height) {
                    let diff = provider.get_cumulative_difficulty_for_block_hash(tip_hash).await?;
                    scores.push((tip_hash.clone(), diff));
                } else {
                    debug!("Block {} is skipped in generate_full_order, is ordered = {}, base topo height = {}", tip_hash, is_ordered, base_topo_height);
                }
            }

            // We sort by ascending cumulative difficulty because it is faster
            // than doing a .reverse() on scores and give correct order for tips processing
            // using our stack impl 
            blockdag::sort_ascending_by_cumulative_difficulty(&mut scores);

            processed.insert(current_hash.clone());
            stack.push_back(current_hash);

            for (tip_hash, _) in scores {
                stack.push_back(tip_hash);
            }
        }

        cache.put((hash.clone(), base.clone(), base_height), full_order.clone());

        Ok(full_order)
    }

    // confirms whether the actual tip difficulty is withing 9% deviation with best tip (reference)
    async fn validate_tips<P: DifficultyProvider>(&self, provider: &P, best_tip: &Hash, tip: &Hash) -> Result<bool, BlockchainError> {
        const MAX_DEVIATION: Difficulty = Difficulty::from_u64(91);
        const PERCENTAGE: Difficulty = Difficulty::from_u64(100);

        let best_difficulty = provider.get_difficulty_for_block_hash(best_tip).await?;
        let block_difficulty = provider.get_difficulty_for_block_hash(tip).await?;

        Ok(best_difficulty * MAX_DEVIATION / PERCENTAGE < block_difficulty)
    }

    // Get difficulty at tips
    // If tips is empty, returns genesis difficulty
    // Find the best tip (highest cumulative difficulty), then its difficulty, timestamp and its own tips
    // Same for its parent, then calculate the difficulty between the two timestamps
    // For Block C, take the timestamp and difficulty from parent block B, and then from parent of B, take the timestamp
    // We take the difficulty from the biggest tip, but compute the solve time from the newest tips
    pub async fn get_difficulty_at_tips<'a, P, I>(&self, provider: &P, tips: I) -> Result<(Difficulty, VarUint), BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + PrunedTopoheightProvider,
        I: IntoIterator<Item = &'a Hash> + ExactSizeIterator + Clone,
        I::IntoIter: ExactSizeIterator
    {
        trace!("get difficulty at tips");

        // Get the height at the tips
        let height = blockdag::calculate_height_at_tips(provider, tips.clone().into_iter()).await?;

        // Get the version at the current height
        let (has_hard_fork, version) = has_hard_fork_at_height(self.get_network(), height);

        if tips.len() == 0 { // Genesis difficulty
            trace!("genesis difficulty");
            return Ok((GENESIS_BLOCK_DIFFICULTY, difficulty::get_covariance_p(version)))
        }

        // if simulator is enabled or we are too low in height, don't calculate difficulty
        if height <= 1 || self.is_simulator_enabled() {
            let difficulty = difficulty::get_minimum_difficulty(self.get_network(), version);
            return Ok((difficulty, difficulty::get_covariance_p(version)))
        }

        if has_hard_fork {
            if let Some(difficulty) = difficulty::get_difficulty_at_hard_fork(self.get_network(), version) {
                trace!("difficulty for hard fork found");
                return Ok((difficulty, difficulty::get_covariance_p(version)))
            }
        }

        // Search the highest difficulty available
        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(provider, tips.clone().into_iter()).await?;
        let biggest_difficulty = provider.get_difficulty_for_block_hash(best_tip).await?;

        // Search the newest tip available to determine the real solve time
        let (_, newest_tip_timestamp) = blockdag::find_newest_tip_by_timestamp(provider, tips.clone().into_iter()).await?;

        // Find the newest tips parent timestamp
        let parent_tips = provider.get_past_blocks_for_block_hash(best_tip).await?;
        let (_, parent_newest_tip_timestamp) = blockdag::find_newest_tip_by_timestamp(provider, parent_tips.iter()).await?;

        let p = provider.get_estimated_covariance_for_block_hash(best_tip).await?;

        // Get the minimum difficulty configured
        let minimum_difficulty = difficulty::get_minimum_difficulty(self.get_network(), version);

        let (difficulty, p_new) = difficulty::calculate_difficulty(
            parent_newest_tip_timestamp,
            newest_tip_timestamp,
            biggest_difficulty,
            p,
            minimum_difficulty,
            version
        );

        Ok((difficulty, p_new))
    }

    // Get the current difficulty target for the next block
    pub async fn get_difficulty(&self) -> Difficulty {
        trace!("get current difficulty");
        let storage = self.storage.read().await;
        debug!("storage read acquired to get difficulty");
        let cache = storage.chain_cache().await;

        cache.difficulty
    }

    // pass in params the already computed block hash and its tips
    // check the difficulty calculated at tips
    // if the difficulty is valid, returns it (prevent to re-compute it)
    pub async fn verify_proof_of_work<'a, P, I>(&self, provider: &P, hash: &Hash, tips: I) -> Result<(Difficulty, VarUint), BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + PrunedTopoheightProvider,
        I: IntoIterator<Item = &'a Hash> + ExactSizeIterator + Clone,
        I::IntoIter: ExactSizeIterator
    {
        trace!("Verifying proof of work for block {}", hash);
        let (difficulty, p) = self.get_difficulty_at_tips(provider, tips).await?;
        trace!("Difficulty at tips: {}", difficulty);
        if check_difficulty(hash, &difficulty)? {
            Ok((difficulty, p))
        } else {
            Err(BlockchainError::InvalidDifficulty)
        }
    }

    // Returns the P2p module used for blockchain if enabled
    pub fn get_p2p(&self) -> &RwLock<Option<Arc<P2pServer<S>>>> {
        &self.p2p
    }

    // Returns the RPC server used for blockchain if enabled
    pub fn get_rpc(&self) -> &RwLock<Option<SharedDaemonRpcServer<S>>> {
        &self.rpc
    }

    // Returns the storage used for blockchain
    pub fn get_storage(&self) -> &RwLock<S> {
        &self.storage
    }

    // Returns the blockchain mempool used
    pub fn get_mempool(&self) -> &RwLock<Mempool> {
        &self.mempool
    }

    // Add a tx to the mempool, its hash will be computed
    pub async fn add_tx_to_mempool(&self, tx: Transaction, broadcast: bool) -> Result<(), BlockchainError> {
        let hash = tx.hash();
        self.add_tx_to_mempool_with_hash(Arc::new(tx), Immutable::Owned(hash), broadcast).await
    }

    // Add a tx to the mempool with the given hash, it is not computed and the TX is transformed into an Arc
    pub async fn add_tx_to_mempool_with_hash(&self, tx: Arc<Transaction>, hash: Immutable<Hash>, broadcast: bool) -> Result<(), BlockchainError> {
        debug!("add tx to mempool with hash {}", hash);
        let storage = self.storage.read().await;
        debug!("storage read acquired to add tx to mempool with hash");
        self.add_tx_to_mempool_with_storage_and_hash(&storage, tx, hash, broadcast).await
    }

    pub async fn add_tx_to_mempool_with_storage_and_hash(&self, storage: &S, tx: Arc<Transaction>, hash: Immutable<Hash>, broadcast: bool) -> Result<(), BlockchainError> {
        debug!("add tx to mempool with storage and hash {} (broadcast = {})", hash, broadcast);
        let tx_size = tx.size();
        if tx_size > MAX_TRANSACTION_SIZE {
            return Err(BlockchainError::TxTooBig(tx_size, MAX_TRANSACTION_SIZE))
        }

        // check that the TX is not already in blockchain
        if storage.is_tx_executed_in_a_block(&hash).await? {
            return Err(BlockchainError::TxAlreadyInBlockchain(hash.into_owned()))
        }

        self.add_tx_to_mempool_internal(storage, tx, tx_size, hash, broadcast).await
    }

    // Add a tx to the mempool with the given hash, it will verify the TX and check that it is not already in mempool or in blockchain
    // and its validity (nonce, balance, etc...)
    pub async fn add_tx_to_mempool_internal(
        &self,
        storage: &S,
        tx: Arc<Transaction>,
        tx_size: usize,
        hash: Immutable<Hash>,
        broadcast: bool
    ) -> Result<(), BlockchainError> {
        debug!("add tx to mempool internal {} (broadcast = {})", hash, broadcast);

        let hash = {
            debug!("locking mempool to add tx");
            let mut mempool = self.mempool.write().await;
            debug!("mempool locked to add tx");

            if mempool.contains_tx(&hash) {
                return Err(BlockchainError::TxAlreadyInMempool(hash.into_owned()))
            }

            let chain_cache = storage.chain_cache().await;

            let stable_topoheight = chain_cache.stable_topoheight;
            let current_topoheight = chain_cache.topoheight;
            let height = chain_cache.height;

            // get the highest nonce available
            // if presents, it means we have at least one tx from this owner in mempool
            if let Some(cache) = mempool.get_cache_for(tx.get_source()) {
                // we accept to delete a tx from mempool if the new one has a higher fee
                if let Some(hash2) = cache.has_tx_with_same_nonce(tx.get_nonce()) {
                    // A TX with the same nonce is already in mempool
                    debug!("TX {} nonce is already used by TX {}", hash, hash2);
                    return Err(BlockchainError::TxNonceAlreadyUsed(tx.get_nonce(), hash2.as_ref().clone()))
                }

                // check that the nonce is in the range
                if !(tx.get_nonce() <= cache.get_max() + 1 && tx.get_nonce() >= cache.get_min()) {
                    debug!("TX {} nonce is not in the range of the pending TXs for this owner, received: {}, expected between {} and {}", hash, tx.get_nonce(), cache.get_min(), cache.get_max());
                    return Err(BlockchainError::InvalidTxNonceMempoolCache(tx.get_nonce(), cache.get_min(), cache.get_max()))
                }
            }

            // Put the hash behind an Arc to share it cheaply
            let hash = hash.into_arc();

            let start = Instant::now();
            let version = get_version_at_height(self.get_network(), height);
            // NOTE: we do not verify / clean against requested base fee
            // to ensure no TX is orphaned, but only delayed until the chain congestion reduce
            mempool.add_tx(storage, &self.environment, stable_topoheight, current_topoheight, FEE_PER_KB, hash.clone(), tx.clone(), tx_size, version).await?;

            debug!("TX {} has been added to the mempool", hash);

            // Record the time taken to add the transaction to the mempool
            histogram!("xelis_mempool_tx_added_ms").record(start.elapsed().as_millis() as f64);
            counter!("xelis_txs_verified").increment(1u64);

            hash
        };

        if broadcast {
            debug!("broadcast new tx {} added in mempool", hash);
            // P2p broadcast to others peers
            if let Some(p2p) = self.p2p.read().await.as_ref() {
                let p2p = p2p.clone();
                let hash = hash.clone();
                spawn_task("tx-notify-p2p", async move {
                    p2p.broadcast_tx_hash(hash).await;
                });
            }

            // broadcast to websocket this tx
            if let Some(rpc) = self.rpc.read().await.as_ref() {
                // Notify miners if getwork is enabled
                if let Some(getwork) = rpc.getwork_server() {
                    let getwork = getwork.clone();
                    spawn_task("tx-notify-new-job", async move {
                        if let Err(e) = getwork.get_handler().notify_new_job_rate_limited().await {
                            debug!("Error while notifying miners for new tx: {}", e);
                        }
                    });
                }

                if rpc.is_event_tracked(&NotifyEvent::TransactionAddedInMempool).await {
                    let json = {
                        let mempool = self.mempool.read().await;
                        let sorted_tx = mempool.get_sorted_tx(&hash)?;
    
                        let data = MempoolTransactionSummary {
                            size: sorted_tx.get_size(),
                            hash: Cow::Borrowed(&hash),
                            fee: tx.get_fee(),
                            source: tx.get_source().as_address(self.network.is_mainnet()),
                            first_seen: sorted_tx.get_first_seen(),
                            fee_per_kb: sorted_tx.get_fee_per_kb()
                        };

                        json!(data)
                    };

                    let rpc = rpc.clone();
                    spawn_task("rpc-notify-tx", async move {
                        if let Err(e) = rpc.notify_clients(&NotifyEvent::TransactionAddedInMempool, json).await {
                            debug!("Error while broadcasting event TransactionAddedInMempool to websocket: {}", e);
                        }
                    });
                }
            }
        }
        
        Ok(())
    }

    // Get a block template for the new block work (mining)
    pub async fn get_block_template(&self, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        debug!("get block template");
        let storage = self.storage.read().await;
        debug!("storage read acquired for get block template");
        self.get_block_template_for_storage(&storage, address).await
    }

    // check that the TX Hash is present in mempool or in chain disk
    pub async fn has_tx(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has tx {}", hash);

        // check in mempool first
        // if its present, returns it
        // Hopefully no deadlock appear here as we lock independently
        debug!("has tx {} in mempool", hash);
        {
            let mempool = self.mempool.read().await;
            debug!("mempool lock acquired for has tx {}", hash);
            if mempool.contains_tx(hash) {
                debug!("TX {} found in mempool", hash);
                return Ok(true)
            }
        }

        // check in storage now
        debug!("has tx {} in storage", hash);
        {
            let storage = self.storage.read().await;
            debug!("storage read acquired for has tx {}", hash);
            if storage.has_transaction(hash).await? {
                debug!("TX {} found in storage", hash);
                return Ok(true)
            }
        }

        debug!("TX {} was not found in storage or mempool", hash);

        Ok(false)
    }

    // Check if the TX is either executed in chain or already present in mempool
    pub async fn is_tx_included(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("is tx {} maybe compatible", hash);

        // check in mempool first
        // if its present, returns it
        debug!("is tx {} included in mempool", hash);
        {
            let mempool = self.mempool.read().await;
            debug!("mempool lock acquired for is tx included {}", hash);
            if mempool.contains_tx(hash) {
                debug!("TX {} found in mempool", hash);
                return Ok(true)
            }
        }

        // check in storage now
        debug!("is tx {} already executed", hash);
        {
            let storage = self.storage.read().await;
            debug!("storage read acquired for is tx {} compatible", hash);
            if storage.is_tx_executed_in_a_block(hash).await? {
                debug!("TX {} found in storage", hash);
                return Ok(true)
            }
        }

        debug!("TX {} is not included anywhere", hash);
        Ok(false)
    }

    // retrieve the TX based on its hash by searching in mempool then on disk
    pub async fn get_tx(&self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        trace!("get tx {} from blockchain", hash);

        // check in mempool first
        // if its present, returns it
        {
            debug!("Locking mempool for get tx {}", hash);
            let mempool = self.mempool.read().await;
            debug!("Mempool locked for get tx {}", hash);
            if let Ok(tx) =  mempool.get_tx(hash) {
                debug!("found {} in mempool", hash);
                return Ok(Immutable::Arc(tx))
            }
        }

        // check in storage now
        {
            debug!("get tx {} storage lock", hash);
            let storage = self.storage.read().await;
            debug!("get tx {} storage read acquired", hash);
            if storage.has_transaction(&hash).await? {
                debug!("tx {} is in storage", hash);
                return storage.get_transaction(hash).await
            }
        }

        Err(BlockchainError::TxNotFound(hash.clone()))
    }

    pub async fn get_block_header_template(&self, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        debug!("get block header template");
        let storage = self.storage.read().await;
        debug!("get block header template lock acquired");
        self.get_block_header_template_for_storage(&storage, address).await
    }

    // Generate a block header template without transactions
    pub async fn get_block_header_template_for_storage(&self, storage: &S, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        trace!("get block header template");
        let start = Instant::now();

        let extra_nonce: [u8; EXTRA_NONCE_SIZE] = rand::thread_rng().gen::<[u8; EXTRA_NONCE_SIZE]>(); // generate random bytes

        let chain_cache = storage.chain_cache().await;
        let tips_set = chain_cache.tips.clone();
        let current_height = chain_cache.height;

        let mut tips = tips_set.into_iter()
            .collect::<Vec<_>>();

        if tips.len() > 1 {
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, tips.iter()).await?.clone();
            debug!("Best tip selected for this block template is {}", best_tip);
            let mut selected_tips = Vec::with_capacity(tips.len());
            for hash in tips {
                if best_tip != hash {
                    if !self.validate_tips(storage, &best_tip, &hash).await? {
                        warn!("Tip {} is invalid, not selecting it because difficulty can't be less than 91% of {}", hash, best_tip);
                        continue;
                    }

                    if !self.is_near_enough_from_main_chain(storage, &hash, current_height).await? {
                        warn!("Tip {} is not selected for mining: too far from mainchain at height: {}", hash, current_height);
                        continue;
                    }
                }
                selected_tips.push(hash);
            }
            tips = selected_tips;

            if tips.is_empty() {
                warn!("No valid tips found for block template, using best tip {}", best_tip);
                tips.push(best_tip);
            }
        }

        let mut sorted_tips: IndexSet<_> = blockdag::sort_tips(storage, tips.into_iter()).await?
            .collect();
        if sorted_tips.len() > TIPS_LIMIT {
            // keep only first 3 heavier tips
            // We drain any tips above the limit
            let len = sorted_tips.len() - TIPS_LIMIT;
            let dropped_tips = sorted_tips.drain(TIPS_LIMIT..)
            .map(|h| h.to_string()).collect::<Vec<String>>().join(", ");
            warn!("too many tips for block generation, using the {} heavier tips: {} available tips", TIPS_LIMIT, len);
            trace!("dropped tips: {}", dropped_tips);
        }

        // find the newest timestamp
        let mut timestamp = 0;
        for tip in sorted_tips.iter() {
            let tip_timestamp = storage.get_timestamp_for_block_hash(tip).await?;
            if tip_timestamp > timestamp {
                timestamp = tip_timestamp;
            }
        }

        // Check that our current timestamp is correct
        let current_timestamp = get_current_time_in_millis();
        if current_timestamp < timestamp {
            warn!("Current timestamp is less than the newest tip timestamp, using newest timestamp from tips");
        } else {
            timestamp = current_timestamp;
        }

        let height = blockdag::calculate_height_at_tips(storage, sorted_tips.iter()).await?;
        let block = BlockHeader::new(get_version_at_height(self.get_network(), height), height, timestamp, sorted_tips, extra_nonce, address, IndexSet::new());

        histogram!("xelis_block_header_template_ms").record(start.elapsed().as_millis() as f64);

        Ok(block)
    }

    // Get the mining block template for miners
    // This function is called when a miner request a new block template
    // We create a block candidate with selected TXs from mempool
    pub async fn get_block_template_for_storage(&self, storage: &S, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        let mut block = self.get_block_header_template_for_storage(storage, address).await?;

        trace!("Locking mempool for building block template");
        let mempool = self.mempool.read().await;
        trace!("Mempool locked for building block template");

        let start = Instant::now();

        // use the mempool cache to get all availables txs grouped by account
        let caches = mempool.get_caches();

        // Build the tx selector using the mempool
        let mut tx_selector = TxSelector::with_capacity(caches.len());
        for cache in caches.values() {
            let cache_txs = cache.get_txs();
            // Map every tx hash to a TxSelectorEntry
            let txs = cache_txs.iter()
                .map(|tx_hash| {
                    let sorted_tx = mempool.get_sorted_tx(tx_hash)?;
                    Ok(TxSelectorEntry {
                        size: sorted_tx.get_size(),
                        hash: tx_hash,
                        tx: sorted_tx.get_tx(),
                        fee_per_kb: sorted_tx.get_fee_per_kb(),
                        fee_limit_per_kb: sorted_tx.get_fee_limit_per_kb(),
                    })
                })
                .collect::<Result<VecDeque<_>, BlockchainError>>()?;

            tx_selector.push_group(txs);
        }

        // size of block
        let mut block_size = block.size();
        let mut total_txs_size = 0;

        // data used to verify txs
        let chain_cache = storage.chain_cache().await;
        let stable_topoheight = chain_cache.stable_topoheight;
        let stable_height = chain_cache.stable_height;
        let topoheight = chain_cache.topoheight;

        trace!("build chain state for block template");

        // V3 is used to group with orphaned TXs from our tips and calculate
        // the base fee
        let is_v3_enabled = block.get_version() >= BlockVersion::V3;
        let base_fee = if is_v3_enabled {
            self.get_required_base_fee(&*storage, block.get_tips().iter()).await?.0
        } else {
            FEE_PER_KB
        };

        let mut chain_state = ChainState::new(storage, &self.environment, stable_topoheight, topoheight, block.get_version(), base_fee);

        if !tx_selector.is_empty() {
            let tx_cache = TxCache::new(storage, &mempool, self.disable_zkp_cache);
            let mut failed_sources = HashSet::new();
            // Search all txs that were processed in tips
            // This help us to determine if a TX was already included or not based on our DAG
            // Hopefully, this should never be triggered because the mempool is cleaned based on our state
            let processed_txs = self.get_all_txs_until_height(storage, stable_height, block.get_tips().iter().cloned(), false, true).await?;

            // Grouped per source each TXs that were contained in blocks (orphaned) tips
            let mut grouped_orphaned_txs = HashMap::new();
            // Keep track of processed sources to avoid re-verifying them
            let mut processed_sources = HashSet::new();

            // If we are not skipping block template TXs verification,
            // we need to detect any orphaned TXs that were processed in the tips
            // This is required in order to include the next TXs
            // We will compute the exact expected balances/nonces after the orphaned TXs
            if !self.skip_block_template_txs_verification && is_v3_enabled {
                for hash in processed_txs.iter() {
                    if storage.is_tx_executed_in_a_block(&hash).await? {
                        // If the TX is executed in a block, we can skip it
                        debug!("Skipping TX {} because it is already executed in a block", hash);
                        continue;
                    }

                    let tx = storage.get_transaction(&hash).await?
                        .into_arc();

                    let source = tx.get_source();
                    grouped_orphaned_txs.entry(source.clone())
                        .or_insert_with(Vec::new)
                        .push((tx, hash));
                }
            }

            while let Some(TxSelectorEntry { size, hash, tx, fee_per_kb, fee_limit_per_kb }) = tx_selector.next() {
                if block_size + HASH_SIZE + total_txs_size + size >= MAX_BLOCK_SIZE || block.txs_hashes.len() >= u16::MAX as usize {
                    debug!("Stopping to include new TXs in this block, final size: {}, count: {}", human_bytes::human_bytes((block_size + total_txs_size) as f64), block.txs_hashes.len());
                    break;
                }

                // Check if the TX is already in the block
                if processed_txs.contains(hash.as_ref()) {
                    debug!("Skipping TX {} because it is already in the DAG branch", hash);
                    continue;
                }

                // Check that the dynamic base fee is valid
                let source = tx.get_source();
                // TODO: rework priority based on fee limit per kb
                if fee_per_kb < base_fee && fee_limit_per_kb < base_fee {
                    debug!("Skipping TX {} because it has a lower fee per kb ({}, limit {}) than required base fee ({})", hash, format_xelis(fee_per_kb), format_xelis(fee_limit_per_kb), format_xelis(base_fee));

                    // Source is marked as failed because if we can't select
                    // the first TX with a lower fee, we can't select any
                    // following TX
                    failed_sources.insert(source);
                    continue;
                }

                if failed_sources.contains(source) {
                    debug!("Skipping TX {} because its source has failed before", hash);
                    continue;
                }

                if !self.skip_block_template_txs_verification {
                    // Check if the TX is valid for this potential block
                    trace!("Checking TX {} with nonce {}, {}", hash, tx.get_nonce(), tx.get_source().as_address(self.network.is_mainnet()));

                    // Verify the TX against the chain state
                    // if we have any orphaned TXs, verify them one time only
                    if let Some(orphaned_txs) = grouped_orphaned_txs.get(&source).filter(|_| processed_sources.insert(source)) {
                        if let Err(e) = Transaction::verify_batch(
                            orphaned_txs.iter(),
                            &mut chain_state,
                            &tx_cache,
                        ).await {
                            warn!("Orphaned TXs for source {} are not valid anymore: {}", source.as_address(self.network.is_mainnet()), e);
                            failed_sources.insert(source);
                            continue;
                        }
                    }

                    // Now verify the current TX
                    if let Err(e) = tx.verify(
                        &hash,
                        &mut chain_state,
                        &tx_cache,
                    ).await {
                        warn!("TX {} ({}) is not valid for mining: {}", hash, source.as_address(self.network.is_mainnet()), e);
                        failed_sources.insert(source);
                        continue;
                    }
                }

                trace!("Selected {} (nonce: {}, fees: {}) for mining", hash, tx.get_nonce(), format_xelis(tx.get_fee()));
                // TODO no clone
                block.txs_hashes.insert(hash.as_ref().clone());
                block_size += HASH_SIZE; // add the hash size
                total_txs_size += size;
            }
        }

        histogram!("xelis_block_header_template_txs_selection_ms").record(start.elapsed().as_millis() as f64);
        counter!("xelis_block_template").increment(1);

        Ok(block)
    }

    // Build a block using the header and search for TXs in mempool and storage
    pub async fn build_block_from_header(&self, header: impl Into<Arc<BlockHeader>>) -> Result<Block, BlockchainError> {
        let header = header.into();
        trace!("Searching TXs for block at height {}", header.get_height());
        let mut transactions = Vec::with_capacity(header.get_txs_count());

        debug!("locking storage for build block from header");
        let storage = self.storage.read().await;
        debug!("storage read acquired for build block from header");
        let mempool = self.mempool.read().await;
        debug!("Mempool lock acquired for building block from header");

        for hash in header.get_txs_hashes() {
            trace!("Searching TX {} for building block", hash);
            // at this point, we don't want to lose/remove any tx, we clone it only
            let tx = if mempool.contains_tx(hash) {
                mempool.get_tx(hash)?
            } else {
                storage.get_transaction(hash).await?
                    .into_arc()
            };

            transactions.push(tx);
        }
        let block = Block::new(header, transactions);
        Ok(block)
    }

    // Pre verify a block by computing its hashes in a dedicated thread
    // Partial check is only done, everything must be rechecked except the hashes
    pub async fn pre_verify_block(&self, block: &Block, block_hash: Option<Immutable<Hash>>) -> Result<PreVerifyBlock, BlockchainError> {
        let _permit = self.pre_verify_block_semaphore.acquire().await?;

        // NOTE: Height will be verified at the add_new_block function
        let expected_version = get_version_at_height(&self.network, block.get_height());
        if expected_version != block.get_version() {
            return Err(BlockchainError::InvalidBlockVersion)
        }

        let algorithm = get_pow_algorithm_for_version(expected_version);

        // Clone the Arc'ed header so we can move it to the thread
        let header = block.get_header().clone();
        // Compute the block hash and the PoW hash in a blocking thread
        spawn_blocking(move || {
            let start = Instant::now();

            let block_hash = block_hash.unwrap_or_else(|| Immutable::Owned(header.hash()));
            let pow_challenge = header.get_pow_challenge();
            let pow_hash = compute_pow_hash(&pow_challenge, algorithm)?;

            histogram!("xelis_block_pow_ms").record(start.elapsed().as_millis() as f64);

            Ok::<_, BlockchainError>(PreVerifyBlock::Partial { block_hash, pow_hash })
        }).await?
    }

    // Add a new block in chain
    // Note that this will lock Storage and Mempool
    // Verification is done using read guards,
    // once the block is fully verified, we can include it
    // in our chain by acquiring a write guard
    pub async fn add_new_block(&self, block: Block, pre_verify: PreVerifyBlock, broadcast: BroadcastOption, mining: bool) -> Result<(), BlockchainError> {
        let start = Instant::now();

        // Expected version for this block
        let version = get_version_at_height(self.get_network(), block.get_height());

        // Verify that the block is on the correct version
        if block.get_version() != version {
            return Err(BlockchainError::InvalidBlockVersion)
        }

        // Either check or use the precomputed one
        let (block_hash, pow_hash) = match pre_verify {
            PreVerifyBlock::Hash(hash) => (hash, None),
            PreVerifyBlock::Partial { block_hash, pow_hash } => (block_hash, Some(pow_hash)),
            PreVerifyBlock::None => (Immutable::Owned(block.hash()), None),
        };

        // Semaphore is required to ensure sequential verification of blocks
        debug!("acquiring add block semaphore");
        let _permit = self.add_block_semaphore.acquire().await?;
        debug!("add block semaphore acquired, locking storage for block verification");
        let storage = self.storage.read().await;

        debug!("Add new block {}", block_hash);
        if storage.has_block_with_hash(&block_hash).await? {
            debug!("Block {} is already in chain!", block_hash);
            return Err(BlockchainError::AlreadyInChain)
        }
        debug!("Block {} is not in chain, processing it", block_hash);

        let current_timestamp = get_current_time_in_millis(); 
        if block.get_timestamp() > current_timestamp + TIMESTAMP_IN_FUTURE_LIMIT { // accept 2s in future
            debug!("Block timestamp is too much in future!");
            return Err(BlockchainError::TimestampIsInFuture(current_timestamp, block.get_timestamp()));
        }

        let tips_count = block.get_tips().len();
        debug!("Tips count for this new {}: {}", block, tips_count);
        // only 3 tips are allowed
        if tips_count > TIPS_LIMIT {
            debug!("Invalid tips count, got {} but maximum allowed is {}", tips_count, TIPS_LIMIT);
            return Err(BlockchainError::InvalidTipsCount(block_hash.into_owned(), tips_count))
        }

        let chain_cache = storage.chain_cache().await;

        let mut current_height = chain_cache.height;
        let mut current_topoheight = chain_cache.topoheight;
        let stable_height = chain_cache.stable_height;
        let stable_topoheight = chain_cache.stable_topoheight;

        if tips_count == 0 && current_height != 0 {
            debug!("Expected at least one previous block for this block {}", block_hash);
            return Err(BlockchainError::ExpectedTips)
        }

        if tips_count > 0 && block.get_height() == 0 {
            debug!("Invalid block height, got height 0 but tips are present for this block {}", block_hash);
            return Err(BlockchainError::BlockHeightZeroNotAllowed)
        }

        if tips_count == 0 && block.get_height() != 0 {
            debug!("Invalid tips count, got {} but current height is {} with block height {}", tips_count, current_height, block.get_height());
            return Err(BlockchainError::InvalidTipsCount(block_hash.into_owned(), tips_count))
        }

        // block contains header and full TXs
        let block_size = block.size();
        if block_size > MAX_BLOCK_SIZE {
            debug!("Block size ({} bytes) is greater than the limit ({} bytes)", block.size(), MAX_BLOCK_SIZE);
            return Err(BlockchainError::InvalidBlockSize(MAX_BLOCK_SIZE, block.size()));
        }

        for tip in block.get_tips() {
            if !storage.has_block_with_hash(tip).await? {
                debug!("This block ({}) has a TIP ({}) which is not present in chain", block_hash, tip);
                return Err(BlockchainError::InvalidTipsNotFound(block_hash.into_owned(), tip.clone()))
            }
        }

        let block_height_by_tips = blockdag::calculate_height_at_tips(&*storage, block.get_tips().iter()).await?;
        if block_height_by_tips != block.get_height() {
            debug!("Invalid block height {}, expected {} for this block {}", block.get_height(), block_height_by_tips, block_hash);
            return Err(BlockchainError::InvalidBlockHeight(block_height_by_tips, block.get_height()))
        }

        if tips_count > 0 {
            debug!("Height by tips: {}, stable height: {}", block_height_by_tips, stable_height);

            if block_height_by_tips < stable_height {
                debug!("Invalid block height by tips {} for this block ({}), its height is in stable height {}", block_height_by_tips, block_hash, stable_height);
                return Err(BlockchainError::InvalidBlockHeightStableHeight)
            }
        }

        // Verify the reachability of the block
        if !self.verify_non_reachability(&*storage, block.get_tips()).await? {
            debug!("{} with hash {} has an invalid reachability", block, block_hash);
            return Err(BlockchainError::InvalidReachability)
        }

        for hash in block.get_tips() {
            let previous_timestamp = storage.get_timestamp_for_block_hash(hash).await?;
            // block timestamp can't be less than previous block.
            if block.get_timestamp() < previous_timestamp {
                debug!("Invalid block timestamp, parent ({}) is less than new block {}", hash, block_hash);
                return Err(BlockchainError::TimestampIsLessThanParent(block.get_timestamp()));
            }

            trace!("calculate distance from mainchain for tips: {}", hash);

            // We're processing the block tips, so we can't use the block height as it may not be in the chain yet
            let height = block_height_by_tips.saturating_sub(1);
            if !self.is_near_enough_from_main_chain(&*storage, hash, height).await? {
                error!("{} with hash {} have deviated too much (current height: {}, block height: {})", block, block_hash, current_height, block_height_by_tips);
                return Err(BlockchainError::BlockDeviation)
            }
        }

        if tips_count > 1 {
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(&*storage, block.get_tips().iter()).await?;
            debug!("Best tip selected for this new block is {}", best_tip);
            for hash in block.get_tips() {
                if best_tip != hash {
                    if !self.validate_tips(&*storage, best_tip, hash).await? {
                        debug!("Tip {} is invalid, difficulty can't be less than 91% of {}", hash, best_tip);
                        return Err(BlockchainError::InvalidTipsDifficulty(block_hash.into_owned(), hash.clone()))
                    }
                }
            }
        }

        // verify PoW and get difficulty for this block based on tips
        let skip_pow = self.skip_pow_verification();
        let pow_hash = if skip_pow {
            // Simulator is enabled, we don't need to compute the PoW hash
            Hash::zero()
        } else if let Some(hash) = pow_hash {
            // PoW Hash was pre computed, use it
            hash
        } else {
            // We have to precompute it ourself
            let start = Instant::now();
            let algorithm = get_pow_algorithm_for_version(version);
            let header = block.get_header().clone();

            // Spawn a thread for the CPU bound PoW computation
            let hash = spawn_blocking(move || {
                let pow_challenge = header.get_pow_challenge();
                compute_pow_hash(&pow_challenge, algorithm)
            }).await??;

            histogram!("xelis_block_pow_ms").record(start.elapsed().as_millis() as f64);
            hash
        };
        debug!("POW hash: {}, skipped: {}", pow_hash, skip_pow);
        let (difficulty, p) = self.verify_proof_of_work(&*storage, &pow_hash, block.get_tips().iter()).await?;
        debug!("PoW is valid for difficulty {}", difficulty);

        // V3 group transactions from orphaned blocks per source to re inject them for verification
        // This is required in case of complex DAG reorgs where we have orphaned blocks with TXs referencing to
        // each other
        // Because these TXs were already verified, their cost should be amortized by the batching verification
        let is_v3_enabled = version >= BlockVersion::V3;

        // Required base fee per KB to prevent low-fee spam attacks
        let (base_fee, block_size_ema) = if is_v3_enabled {
            self.get_required_base_fee(&*storage, block.get_tips().iter()).await?
        } else {
            (FEE_PER_KB, self.get_blocks_size_ema_at_tips(&*storage, block.get_tips().iter()).await?)
        };

        // Transaction verification
        // Here we are going to verify all TXs in the block
        // For this, we must select TXs that are not doing collisions with other TXs in block
        // TX already added in the same DAG branch (block tips) are rejected because miner should be aware of it
        // TXs that are already executed in stable height are also rejected whatever DAG branch it is
        // If the TX is executed by another branch, we skip the verification because DAG will choose which branch will execute the TX
        {
            let hashes_len = block.get_txs_hashes().len();
            let txs_len = block.get_transactions().len();
            if  hashes_len != txs_len {
                debug!("Block {} has an invalid block header, transactions count mismatch (expected {} got {})!", block_hash, txs_len, hashes_len);
                return Err(BlockchainError::InvalidBlockTxs(hashes_len, txs_len));
            }

            // Serializer support only up to u16::MAX txs per block
            let limit = u16::MAX as usize;
            if txs_len > limit {
                debug!("Block {} has an invalid block header, transactions count is bigger than limit (expected max {} got {})!", block_hash, limit, hashes_len);
                return Err(BlockchainError::InvalidBlockTxs(limit, txs_len));
            }

            trace!("verifying {} TXs in block {}", txs_len, block_hash);

            // V2 helps us to determine if we should retrieve all TXs from parents
            // that are not only executed, but also just in block tips to prevent re integration
            // as we know that if current block would be accepted, its tips would be also executed in DAG
            let is_v2_enabled = version >= BlockVersion::V2;

            // All transactions grouped per source key
            // used for batch verifications
            let mut txs_grouped = HashMap::new();

            // Cache to retrieve only one time all TXs hashes until stable height from our TIPS
            // This include all TXs that were executed (or not if any TIP branch is orphaned)
            let parents_txs = if !block.get_txs_hashes().is_empty() {
                debug!("Loading all TXs until height {} for block {} (executed only: {})", stable_height, block_hash, !is_v2_enabled);
                self.get_all_txs_until_height(
                    &*storage,
                    stable_height,
                    block.get_tips().iter().cloned(),
                    !is_v2_enabled,
                    is_v3_enabled,
                ).await?
            } else {
                IndexSet::new()
            };

            if is_v3_enabled {
                // if V3 is enabled, we should also group the TXs by source
                // to re inject them in case of orphaned blocks
                debug!("Grouping all TXs from parents by source for block {}", block_hash);
                for hash in parents_txs.iter() {
                    if storage.is_tx_executed_in_a_block(hash).await? {
                        debug!("TX {} from parent is executed, skipping it", hash);
                        continue;
                    }

                    let tx = storage.get_transaction(hash).await?
                        .into_arc();

                    let source = tx.get_source();
                    txs_grouped.entry(Cow::Owned(source.clone()))
                        .or_insert_with(Vec::new)
                        .push((tx, hash));
                }
            }

            let mut total_outputs = 0;
            let mut total_txs = 0;

            for (tx, hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) {
                let tx_size = tx.size();
                if tx_size > MAX_TRANSACTION_SIZE {
                    return Err(BlockchainError::TxTooBig(tx_size, MAX_TRANSACTION_SIZE))
                }

                // verification that the real TX Hash is the same as in block header (and also check the correct order)
                let tx_hash = tx.hash();
                if tx_hash != *hash {
                    debug!("Invalid tx {} vs {} in block header", tx_hash, hash);
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                }

                debug!("Verifying TX {}", tx_hash);
                // check that the TX included is not executed in stable height
                let is_executed = storage.is_tx_executed_in_a_block(hash).await?;
                if is_executed {
                    let block_executor = storage.get_block_executor_for_tx(hash).await?;
                    debug!("Tx {} was executed in {}", hash, block_executor);
                    let block_executor_height = storage.get_height_for_block_hash(&block_executor).await?;
                    // if the tx was executed below stable height, reject whole block!
                    if block_executor_height <= stable_height {
                        debug!("Block {} contains a dead tx {} from stable height {}", block_hash, tx_hash, stable_height);
                        return Err(BlockchainError::DeadTxFromStableHeight(block_hash.into_owned(), tx_hash, stable_height, block_executor))
                    }
                }

                // If the TX is already executed,
                // we should check that the TX is not in block tips
                // For v2 and above, all TXs that are presents in block TIPs are rejected
                if is_v2_enabled || (is_executed && !is_v2_enabled) {
                    // miner knows this tx was already executed because its present in block tips
                    // reject the whole block
                    if parents_txs.contains(&tx_hash) {
                        debug!("Malicious Block {} formed, contains a dead tx {}, is executed: {}", block_hash, tx_hash, is_executed);
                        return Err(BlockchainError::DeadTxFromTips(block_hash.into_owned(), tx_hash))
                    } else if is_executed {
                        // otherwise, all looks good but because the TX was executed in another branch, we skip verification
                        // DAG will choose which branch will execute the TX
                        debug!("TX {} was executed in another branch, skipping verification", tx_hash);

                        // because TX was already validated & executed and is not in block tips
                        // we can safely skip the verification of this TX
                        continue;
                    }
                }

                total_outputs += tx.get_outputs_count();
                total_txs += 1;
                // Transactions are behind a Arc because they are
                // cloned for verify_batch which run a spawn_blocking thread
                txs_grouped.entry(Cow::Borrowed(tx.get_source()))
                    .or_insert_with(Vec::new)
                    .push((Arc::clone(tx), hash));
            }

            if !txs_grouped.is_empty() {
                debug!("proof verifications of {} TXs from {} sources with {} outputs in block {}", total_txs, txs_grouped.len(), total_outputs, block_hash);

                debug!("locking mempool read mode for cache usage");
                let mempool = self.mempool.read().await;
                debug!("mempool locked for cache usage");

                let tx_cache = TxCache::new(&*storage, &mempool, self.disable_zkp_cache);

                // Track how much time it takes to verify them all
                let start = Instant::now();

                // If multi thread is enabled and we have more than one source
                // Otherwise its not worth-it to move it on another thread
                if self.txs_verification_threads_count > 1 && txs_grouped.len() > 1 && is_multi_threads_supported() {
                    let mut batches_count = txs_grouped.len();
                    if batches_count > self.txs_verification_threads_count {
                        debug!("Batches count ({}) is above configured threads ({}), capping it", batches_count, self.txs_verification_threads_count);
                        batches_count = self.txs_verification_threads_count;
                    }

                    debug!("using multi-threading mode to verify the transactions in {} batches", batches_count);
                    let mut batches = vec![Vec::new(); batches_count];

                    let mut i = 0;
                    // TODO: load balance more!
                    for group in txs_grouped.into_values() {
                        batches[i % batches_count].extend(group);
                        i += 1;
                    }

                    let storage = &*storage;
                    let environment = &self.environment;
                    let cache = &tx_cache;

                    // We run the batches in concurrent tasks
                    // But, because Transaction#verify_batch is actually spawning a blocking thread
                    // it will be multi-threaded by N threads
                    stream::iter(batches.into_iter().map(Ok))
                        .try_for_each_concurrent(self.txs_verification_threads_count, async |txs| {
                            let mut chain_state = ChainState::new(storage, environment, stable_topoheight, current_topoheight, version, base_fee);
                            Transaction::verify_batch(txs.iter(), &mut chain_state, cache).await
                        }).await?;
                } else {
                    // Verify all valid transactions in one batch
                    let mut chain_state = ChainState::new(&*storage, &self.environment, stable_topoheight, current_topoheight, version, base_fee);
                    let iter = txs_grouped.values()
                        .flatten();
                    Transaction::verify_batch(iter, &mut chain_state, &tx_cache).await?;
                }

                debug!("Verified {} transactions in {}ms", total_txs, start.elapsed().as_millis());

                // Record metrics
                counter!("xelis_txs_verified").increment(total_txs as u64);
                histogram!("xelis_txs_verification_ms").record(start.elapsed().as_millis() as f64);
            }
        }

        // Compute cumulative difficulty for block
        // We retrieve it to pass it as a param below for p2p broadcast
        let cumulative_difficulty: CumulativeDifficulty = if tips_count == 0 {
            GENESIS_BLOCK_DIFFICULTY.into()
        } else {
            debug!("Computing cumulative difficulty for block {}", block_hash);
            let (base, base_height) = self.find_common_base(&*storage, block.get_tips()).await?;
            debug!("Common base found: {}, height: {}, calculating cumulative difficulty", base, base_height);
            self.find_tip_work_score(
                &*storage,
                &block_hash,
                block.get_tips().iter(),
                Some(difficulty),
                &base,
                base_height
            ).await?.1
        };
        debug!("Cumulative difficulty for block {}: {}", block_hash, cumulative_difficulty);

        let (block, txs) = block.split();
        let block_hash = block_hash.into_arc();

        // Broadcast to p2p nodes the block asap as its valid
        if broadcast.p2p() {
            debug!("Broadcasting block");
            if let Some(p2p) = self.p2p.read().await.as_ref() {
                trace!("P2p locked, broadcasting in new task");
                let p2p = p2p.clone();
                let pruned_topoheight = storage.get_pruned_topoheight().await?;
                let block = block.clone();
                let block_hash = block_hash.clone();
                spawn_task("broadcast-block", async move {
                    p2p.broadcast_block(
                        &block,
                        cumulative_difficulty,
                        current_topoheight,
                        current_height.max(block.get_height()),
                        pruned_topoheight,
                        block_hash,
                        mining
                    ).await;
                });
            }
        } else {
            debug!("Not broadcasting block {} because broadcast is disabled", block_hash);
        }

        // Calculate the new block size ema for this block
        // so it can be used as base for next block
        let mut ema = BlockSizeEma::default(block_size_ema);
        ema.add(block_size);
        let new_block_size_ema = ema.current();

        // If we have reached this part, it means the block is valid and we can start integrating it

        // Start by dropping the read guard
        // Because we will re-lock it in write mode
        drop(storage);

        counter!("xelis_block_added").increment(1);

        let mut storage = self.storage.write().await;

        // Save transactions & block
        {
            debug!("Saving block {} on disk", block_hash);
            let start = Instant::now();
            storage.save_block(block.clone(), &txs, difficulty, cumulative_difficulty, p, new_block_size_ema, Immutable::Arc(block_hash.clone())).await?;
            storage.add_block_execution_to_order(&block_hash).await?;

            histogram!("xelis_block_store_ms").record(start.elapsed().as_millis() as f64);
        }

        debug!("Block {} saved on disk", block_hash);

        let mut tips = storage.get_tips().await?;
        // TODO: best would be to not clone
        tips.insert(block_hash.as_ref().clone());
        for hash in block.get_tips() {
            tips.remove(hash);
        }
        debug!("New tips: {}", tips.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","));

        let (base_hash, base_height) = self.find_common_base(&*storage, &tips).await?;
        debug!("New base hash: {}, height: {}", base_hash, base_height);
        let best_tip = self.find_best_tip(&*storage, &tips, &base_hash, base_height).await?;
        debug!("Best tip selected: {}", best_tip);

        let base_topo_height = storage.get_topo_height_for_hash(&base_hash).await?;
        // generate a full order until base_topo_height
        let mut full_order = self.generate_full_order(&*storage, &best_tip, &base_hash, base_height, base_topo_height).await?;
        debug!("Generated full order size: {}, with base ({}) topo height: {}", full_order.len(), base_hash, base_topo_height);
        trace!("Full order: {}", full_order.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "));

        // rpc server lock
        let rpc_server = self.rpc.read().await;
        let should_track_events = if let Some(rpc) = rpc_server.as_ref() {
            rpc.get_tracked_events().await
        } else {
            HashSet::new()
        };

        // track all events to notify websocket
        let mut events: HashMap<NotifyEvent, Vec<Value>> = HashMap::new();
        // Track all orphaned transactions
        // We keep in order all orphaned txs to try to re-add them in the mempool
        let mut orphaned_transactions = IndexSet::new();

        // order the DAG (up to TOP_HEIGHT - STABLE_LIMIT)
        let mut highest_topo = 0;
        // Tells if the new block added is ordered in DAG or not
        let block_is_ordered = full_order.contains(block_hash.as_ref());
        // Track if the DAG has been reorganized
        let mut dag_is_overwritten = base_topo_height == 0;
        {
            let start = Instant::now();
            let mut skipped = 0;
            // detect which part of DAG reorg stay, for other part, undo all executed txs
            debug!("Detecting stable point of DAG and cleaning txs above it");
            {
                let mut topoheight = base_topo_height;
                while topoheight <= current_topoheight {
                    let hash_at_topo = storage.get_hash_at_topo_height(topoheight).await?;
                    trace!("Cleaning txs at topoheight {} ({})", topoheight, hash_at_topo);
                    if !dag_is_overwritten {
                        if let Some(order) = full_order.first() {
                            // Verify that the block is still at the same topoheight
                            if storage.is_block_topological_ordered(order).await? && *order == hash_at_topo {
                                trace!("Hash {} at topo {} stay the same, skipping cleaning", hash_at_topo, topoheight);
                                // remove the hash from the order because we don't need to recompute it
                                full_order.shift_remove_index(0);
                                topoheight += 1;
                                skipped += 1;
                                continue;
                            }
                        }
                        // if we are here, it means that the block was re-ordered
                        dag_is_overwritten = true;
                    }

                    debug!("Cleaning transactions executions at topo height {} (block {})", topoheight, hash_at_topo);

                    let block = storage.get_block_header_by_hash(&hash_at_topo).await?;

                    // Block may be orphaned if its not in the new full order set
                    let is_orphaned = !full_order.contains(&hash_at_topo);
                    // Notify if necessary that we have a block orphaned
                    if is_orphaned && should_track_events.contains(&NotifyEvent::BlockOrphaned) {
                        let value = json!(BlockOrphanedEvent {
                            block_hash: Cow::Borrowed(&hash_at_topo),
                            old_topoheight: topoheight,
                        });
                        events.entry(NotifyEvent::BlockOrphaned).or_insert_with(Vec::new).push(value);
                    }

                    // mark txs as unexecuted if it was executed in this block
                    for tx_hash in block.get_txs_hashes() {
                        if storage.is_tx_executed_in_block(tx_hash, &hash_at_topo).await? {
                            debug!("Removing execution of {}", tx_hash);
                            storage.unmark_tx_from_executed(tx_hash).await?;
                            storage.delete_contract_logs_for_caller(tx_hash).await?;

                            if is_orphaned {
                                debug!("Tx {} is now marked as orphaned", tx_hash);
                                orphaned_transactions.insert(tx_hash.clone());
                            }
                        }
                    }

                    // Delete changes made by this block
                    storage.delete_versioned_data_at_topoheight(topoheight).await?;

                    topoheight += 1;
                }

                // Only clear the versioned data caches if we delete any data
                if dag_is_overwritten {
                    storage.clear_versioned_data_caches().await?;
                }
            }

            // This is used to verify that each nonce is used only one time
            let mut nonce_checker = NonceChecker::new();
            // Side blocks counter per height
            let mut side_blocks: HashMap<u64, u64> = HashMap::new();
            let mut total_txs_executed = 0;
            let mut total_txs_execution_time = 0;

            // time to order the DAG that is moving
            debug!("Ordering blocks based on generated DAG order ({} blocks)", full_order.len());
            for (i, hash) in full_order.into_iter().enumerate() {
                highest_topo = base_topo_height + skipped + i as u64;

                // if block is not re-ordered and it's not genesis block
                // because we don't need to recompute everything as it's still good in chain
                if !dag_is_overwritten && tips_count != 0 && storage.is_block_topological_ordered(&hash).await? && storage.get_topo_height_for_hash(&hash).await? == highest_topo {
                    trace!("Block ordered {} stay at topoheight {}. Skipping...", hash, highest_topo);
                    continue;
                }
                dag_is_overwritten = true;

                trace!("Ordering block {} at topoheight {}", hash, highest_topo);

                storage.set_topo_height_for_block(&hash, highest_topo).await?;
                let past_emitted_supply = if highest_topo == 0 {
                    0
                } else {
                    storage.get_supply_at_topo_height(highest_topo - 1).await?
                };

                // Block for this hash
                let block = storage.get_block_by_hash(&hash).await?;

                // Reward the miner of this block
                // We have a decreasing block reward if there is too much side block
                let is_side_block = self.is_side_block_internal(&*storage, &hash, highest_topo).await?;
                let height = block.get_height();
                let side_blocks_count = match side_blocks.entry(height) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let mut count = 0;
                        let blocks_at_height = storage.get_blocks_at_height(height).await?;
                        for block in blocks_at_height {
                            if block != hash && self.is_side_block_internal(&*storage, &block, highest_topo).await? {
                                count += 1;
                                debug!("Found side block {} at height {}", block, height);
                            }
                        }

                        entry.insert(count)
                    },
                };

                let block_reward = self.internal_get_block_reward(past_emitted_supply, is_side_block, *side_blocks_count, block.get_version()).await?;
                trace!("set block {} reward to {} at {} (height {}, side block: {}, {} {}%)", hash, block_reward, highest_topo, height, is_side_block, side_blocks_count, side_block_reward_percentage(*side_blocks_count));
                if is_side_block {
                    *side_blocks_count += 1;
                }

                // Chain State used for the verification
                trace!("building chain state to execute TXs in block {}", block_hash);
                let mut chain_state = ApplicableChainState::new(
                    &mut *storage,
                    &self.environment,
                    base_topo_height,
                    highest_topo,
                    version,
                    &hash,
                    &block,
                    base_fee,
                );

                // Increase the circulating supply with the block reward
                let changes = chain_state.get_asset_changes_for(&XELIS_ASSET, true).await?;
                changes.circulating_supply.1 += block_reward;
                changes.circulating_supply.0.mark_updated();

                total_txs_executed += block.get_txs_count();

                // Execute all the scheduled executions registered
                // at the current topoheight
                chain_state.process_scheduled_executions().await?;

                // compute rewards & execute txs
                for (tx, tx_hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) { // execute all txs
                    // Link the transaction hash to this block
                    if !chain_state.get_mut_storage().add_block_linked_to_tx_if_not_present(&tx_hash, &hash).await? {
                        trace!("Block {} is now linked to tx {}", hash, tx_hash);
                    }

                    // check that the tx was not yet executed in another tip branch
                    if chain_state.get_storage().is_tx_executed_in_a_block(tx_hash).await? {
                        trace!("Tx {} was already executed in a previous block, skipping...", tx_hash);
                    } else {
                        // tx was not executed, but lets check that it is not a potential double spending
                        // check that the nonce is not already used
                        if !nonce_checker.use_nonce(chain_state.get_storage(), tx.get_source(), tx.get_nonce(), highest_topo).await? {
                            warn!("Malicious TX {}, it is a potential double spending with same nonce {}, skipping...", tx_hash, tx.get_nonce());
                            // TX will be orphaned
                            orphaned_transactions.insert(tx_hash.clone());
                            continue;
                        }

                        let start = Instant::now();
                        // Execute the transaction by applying changes in storage
                        debug!("Executing tx {} in block {} with nonce {}", tx_hash, hash, tx.get_nonce());
                        if let Err(e) = tx.apply_with_partial_verify(tx_hash, &mut chain_state).await {
                            warn!("Error while executing TX {} with current DAG org: {}", tx_hash, e);
                            // TX may be orphaned if not added again in good order in next blocks
                            orphaned_transactions.insert(tx_hash.clone());
                            continue;
                        }
                        total_txs_execution_time += start.elapsed().as_micros();

                        // Calculate the new nonce
                        // This has to be done in case of side blocks where TX B would be before TX A
                        let expected_next_nonce = nonce_checker.get_new_nonce(tx.get_source(), self.network.is_mainnet())?;
                        let next_nonce = tx.get_nonce() + 1;
                        if expected_next_nonce != next_nonce {
                            warn!("TX {} has a nonce {}, but the next nonce is {}, forcing it...", tx_hash, next_nonce, expected_next_nonce);
                            chain_state.as_mut().update_account_nonce(tx.get_source(), expected_next_nonce).await?;
                        }

                        // mark tx as executed
                        chain_state.get_mut_storage().mark_tx_as_executed_in_block(tx_hash, &hash).await?;

                        // Delete the transaction from  the list if it was marked as orphaned
                        if orphaned_transactions.shift_remove(tx_hash) {
                            trace!("Transaction {} was marked as orphaned, but got executed again", tx_hash);
                        }

                        // if the rpc_server is enable, track events
                        if should_track_events.contains(&NotifyEvent::TransactionExecuted) {
                            let value = json!(TransactionExecutedEvent {
                                tx_hash: Cow::Borrowed(&tx_hash),
                                block_hash: Cow::Borrowed(&hash),
                                topoheight: highest_topo,
                            });
                            events.entry(NotifyEvent::TransactionExecuted).or_insert_with(Vec::new).push(value);
                        }

                        // Check TX type for RPC events
                        match tx.get_data() {
                            TransactionType::InvokeContract(payload) => {
                                let event = NotifyEvent::InvokeContract {
                                    contract: payload.contract.clone(),
                                };

                                if should_track_events.contains(&event) {
                                    let is_mainnet = self.network.is_mainnet();

                                    if let Some(contract_outputs) = chain_state.get_contract_logs_for_tx(&tx_hash) {
                                        let contract_outputs = contract_outputs.into_iter()
                                        .map(|output| RPCContractLog::from_log(output, is_mainnet))
                                        .collect::<Vec<_>>();

                                        let value = json!(InvokeContractEvent {
                                            tx_hash: Cow::Borrowed(&tx_hash),
                                            block_hash: Cow::Borrowed(&hash),
                                            topoheight: highest_topo,
                                            contract_outputs,
                                        });

                                        events.entry(event)
                                            .or_insert_with(Vec::new)
                                            .push(value);
                                    }
                                }
                            },
                            TransactionType::DeployContract(_) => {
                                if should_track_events.contains(&NotifyEvent::DeployContract) {
                                    let value = json!(NewContractEvent {
                                        contract: Cow::Borrowed(&tx_hash),
                                        block_hash: Cow::Borrowed(&hash),
                                        topoheight: highest_topo,
                                    });
                                    events.entry(NotifyEvent::DeployContract)
                                        .or_insert_with(Vec::new)
                                        .push(value);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Execute all the scheduled executions for the block end
                chain_state.process_executions_at_block_end().await?;

                let dev_fee_percentage = get_block_dev_fee(block.get_height());
                // Dev fee are only applied on block reward
                // Transaction fees are not affected by dev fee
                let mut miner_reward = block_reward;
                if dev_fee_percentage != 0 {
                    let dev_fee_part = block_reward * dev_fee_percentage / 100;
                    chain_state.reward_miner(&DEV_PUBLIC_KEY, dev_fee_part).await?;
                    miner_reward -= dev_fee_part;    
                }

                // reward the miner
                // Miner gets the block reward + total fees + gas fee
                let gas_fee = chain_state.get_gas_fee();
                let total_fees = chain_state.get_total_fees();
                chain_state.reward_miner(block.get_miner(), miner_reward + total_fees + gas_fee).await?;

                // Fire all the contract events
                {
                    let start = Instant::now();
                    let contract_tracker = chain_state.get_contract_tracker();
                    let is_mainnet = self.network.is_mainnet();

                    // We want to only fire one event per key/hash pair
                    if should_track_events.contains(&NotifyEvent::NewAsset) {
                        let entry = events.entry(NotifyEvent::NewAsset)
                            .or_insert_with(Vec::new);

                        for asset in contract_tracker.assets_created.iter() {
                            let value = json!(NewAssetEvent {
                                asset: Cow::Borrowed(asset),
                                block_hash: Cow::Borrowed(&hash),
                                topoheight: highest_topo,
                            });

                            entry.push(value);
                        }
                    }

                    for ((caller, contract), transfers) in contract_tracker.contracts_transfers.iter() {
                        for (key, assets) in transfers.iter() {
                            let event = NotifyEvent::ContractTransfers {
                                address: key.as_address(is_mainnet),
                            };

                            if should_track_events.contains(&event) {
                                let entry = events.entry(event)
                                    .or_insert_with(Vec::new);

                                let value = json!(ContractTransfersEvent {
                                    contract: Cow::Borrowed(contract),
                                    caller: Cow::Borrowed(caller),
                                    transfers: Cow::Borrowed(assets),
                                    block_timestamp: block.get_timestamp(),
                                    block_hash: Cow::Borrowed(&hash),
                                    topoheight: highest_topo,
                                });

                                entry.push(value);
                            }
                        }
                    }

                    let caches = chain_state.get_contracts_cache();
                    for (contract, cache) in caches {
                        for (id, elements) in cache.events.iter() {
                            let event = NotifyEvent::ContractEvent {
                                contract: (*contract).clone(),
                                id: *id
                            };

                            if should_track_events.contains(&event) {
                                let entry = events.entry(event)
                                    .or_insert_with(Vec::new);

                                for el in elements {
                                    entry.push(json!(ContractEvent {
                                        topoheight: highest_topo,
                                        block_hash: Cow::Borrowed(&hash),
                                        data: Cow::Borrowed(el)
                                    }));
                                }
                            }
                        }
                    }

                    debug!("Processed contracts events in {}ms", start.elapsed().as_millis());
                }

                // apply changes from Chain State
                chain_state.apply_changes(past_emitted_supply, block_reward).await?;

                if should_track_events.contains(&NotifyEvent::BlockOrdered) {
                    let value = json!(BlockOrderedEvent {
                        block_hash: Cow::Borrowed(&hash),
                        block_type: get_block_type_for_block(self, &*storage, &hash).await.unwrap_or(BlockType::Normal),
                        topoheight: highest_topo,
                    });

                    events.entry(NotifyEvent::BlockOrdered)
                        .or_insert_with(Vec::new)
                        .push(value);
                }
            }

            let elapsed = Duration::from_micros(total_txs_execution_time as _);
            debug!("Executed {} TXs in {:?}", total_txs_executed, elapsed);

            // Record metrics
            counter!("xelis_txs_executed").increment(total_txs_executed as u64);
            histogram!("xelis_txs_execution_ms").record(elapsed.as_millis() as f64);
            histogram!("xelis_dag_ordering_ms").record(start.elapsed().as_millis() as f64);
        }

        let best_height = storage.get_height_for_block_hash(best_tip).await?;
        let mut new_tips = Vec::new();
        for hash in tips {
            if self.is_near_enough_from_main_chain(&*storage, &hash, current_height).await? {
                trace!("Adding {} as new tips", hash);
                new_tips.push(hash);
            } else {
                warn!("Rusty TIP declared stale {} with best height: {}", hash, best_height);
            }
        }

        tips = HashSet::new();
        debug!("find best tip by cumulative difficulty");
        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(&*storage, new_tips.iter()).await?.clone();
        for hash in new_tips {
            if best_tip != hash {
                if !self.validate_tips(&*storage, &best_tip, &hash).await? {
                    warn!("Rusty TIP {} declared stale", hash);
                } else {
                    debug!("Tip {} is valid, adding to final Tips list", hash);
                    tips.insert(hash);
                }
            }
        }
        tips.insert(best_tip);

        // save highest topo height
        debug!("Highest topo height found: {}", highest_topo);
        let chain_topoheight_extended = current_height == 0 || highest_topo > current_topoheight;
        if chain_topoheight_extended {
            debug!("Blockchain height extended, current topoheight is now {} (previous was {})", highest_topo, current_topoheight);
            storage.set_top_topoheight(highest_topo).await?;
            current_topoheight = highest_topo;
        }

        // If block is directly orphaned
        // Mark all TXs ourself as linked to it
        if !block_is_ordered {
            debug!("Block {} is orphaned, marking all TXs as linked to it", block_hash);
            for tx_hash in block.get_txs_hashes() {
                storage.add_block_linked_to_tx_if_not_present(&tx_hash, &block_hash).await?;
            }
        }

        // auto prune mode
        if let Some(keep_only) = self.auto_prune_keep_n_blocks.filter(|_| chain_topoheight_extended) {
            // check that the topoheight is greater than the safety limit
            // and that we can prune the chain using the config while respecting the safety limit
            if current_topoheight % keep_only == 0 && current_topoheight - keep_only > 0 {
                info!("Auto pruning chain until topoheight {} (keep only {} blocks)", current_topoheight - keep_only, keep_only);
                let start = Instant::now();
                if let Err(e) = self.prune_until_topoheight_for_storage(current_topoheight - keep_only, &mut *storage).await {
                    warn!("Error while trying to auto prune chain: {}", e);
                }

                info!("Auto pruning done in {}ms", start.elapsed().as_millis());
            }
        }

        debug!("Storing new tips in storage");
        // Store the new tips available
        storage.store_tips(&tips).await?;

        let chain_height_extended = current_height == 0 || block.get_height() > current_height;
        if chain_height_extended {
            debug!("storing new top height {}", block.get_height());
            storage.set_top_height(block.get_height()).await?;
            current_height = block.get_height();
        }

        // update stable height and difficulty in cache
        {
            if should_track_events.contains(&NotifyEvent::StableHeightChanged) {
                // detect the change in stable height
                if base_height != stable_height {
                    let value = json!(StableHeightChangedEvent {
                        previous_stable_height: stable_height,
                        new_stable_height: base_height
                    });
                    events.entry(NotifyEvent::StableHeightChanged).or_insert_with(Vec::new).push(value);
                }
            }

            if should_track_events.contains(&NotifyEvent::StableTopoHeightChanged) {
                // detect the change in stable topoheight
                if base_topo_height != stable_topoheight {
                    let value = json!(StableTopoHeightChangedEvent {
                        previous_stable_topoheight: stable_topoheight,
                        new_stable_topoheight: base_topo_height
                    });
                    events.entry(NotifyEvent::StableTopoHeightChanged).or_insert_with(Vec::new).push(value);
                }
            }

            debug!("update difficulty in cache for new tips");
            let (difficulty, _) = self.get_difficulty_at_tips(&*storage, tips.iter()).await?;

            // Update caches
            let chain_cache = storage.chain_cache_mut().await?;
            chain_cache.stable_height = base_height;
            chain_cache.stable_topoheight = base_topo_height;
            chain_cache.difficulty = difficulty;
            chain_cache.tips = tips;

            if chain_height_extended {
                chain_cache.height = current_height;
            }

            if chain_topoheight_extended {
                chain_cache.topoheight = current_topoheight;
            }
        }

        // Check if the event is tracked
        let orphan_event_tracked = should_track_events.contains(&NotifyEvent::TransactionOrphaned);

        // Now we can try to add back all transactions that got orphaned during the chain reorg
        {
            counter!("xelis_orphaned_txs").increment(orphaned_transactions.len() as u64);

            let mut mempool = self.mempool.write().await;

            let start = Instant::now();
            let orphaned = mempool.try_add_back_txs(&*storage, orphaned_transactions.into_iter(), &self.environment, base_topo_height, highest_topo, version, FEE_PER_KB).await?;
            if !orphan_event_tracked {
                for (tx_hash, tx) in orphaned {
                    // We couldn't add it back to mempool, let's notify this event
                    let data = RPCTransaction::from_tx(&tx, Cow::Borrowed(&tx_hash), tx.size(), storage.is_mainnet());
                    let data = GetTransactionResult {
                        blocks: None,
                        executed_in_block: None,
                        in_mempool: false,
                        first_seen: None,
                        data,
                    };
                    events.entry(NotifyEvent::TransactionOrphaned).or_insert_with(Vec::new).push(json!(data));
                }
            }
            histogram!("xelis_orphaned_txs_add_back_ms").record(start.elapsed().as_millis() as f64);
        }

        // Clean mempool from old txs if the DAG has been updated
        let mempool_deleted_txs = if chain_topoheight_extended {
            debug!("Locking mempool write mode");
            let mut mempool = self.mempool.write().await;
            debug!("mempool write mode ok");
            let version = get_version_at_height(self.get_network(), current_height);

            let start = Instant::now();
            // NOTE: we don't remove any under-paid TX, they stay in mempool until fixed
            let res = mempool.clean_up(&*storage, &self.environment, base_topo_height, highest_topo, version, FEE_PER_KB, dag_is_overwritten).await?;
            debug!("Took {:?} to clean mempool!", start.elapsed());
            histogram!("xelis_mempool_clean_up_ms").record(start.elapsed().as_millis() as f64);

            res
        } else {
            Vec::new()
        };

        if orphan_event_tracked {
            for (tx_hash, sorted_tx) in mempool_deleted_txs {
                // Verify that the TX was not executed in a block
                if storage.is_tx_executed_in_a_block(&tx_hash).await? {
                    trace!("Transaction {} was executed in a block, skipping orphaned event", tx_hash);
                    continue;
                }

                let data = RPCTransaction::from_tx(&sorted_tx.get_tx(), Cow::Borrowed(&tx_hash), sorted_tx.get_size(), storage.is_mainnet());
                let data = GetTransactionResult {
                    blocks: None,
                    executed_in_block: None,
                    in_mempool: false,
                    first_seen: Some(sorted_tx.get_first_seen()),
                    data,
                };
                events.entry(NotifyEvent::TransactionOrphaned).or_insert_with(Vec::new).push(json!(data));
            }
        }

        // Flush to the disk
        if self.flush_db_every_n_blocks.is_some_and(|n| current_topoheight % n == 0) {
            debug!("force flushing storage");
            storage.flush().await?;
        }

        let elapsed = start.elapsed().as_millis();
        info!("Processed block {} at height {} in {}ms with {} txs (DAG: {})", block_hash, block.get_height(), elapsed, block.get_txs_count(), block_is_ordered);

        // Record metrics
        histogram!("xelis_block_processing_ms").record(elapsed as f64);
        gauge!("xelis_block_height").set(current_height as f64);
        gauge!("xelis_block_topoheight").set(current_topoheight as f64);

        if let Some(p2p) = self.p2p.read().await.as_ref().filter(|_| broadcast.p2p()) {
            trace!("P2p locked, ping peers");
            let p2p = p2p.clone();
            spawn_task("notify-ping-peers", async move {
                p2p.ping_peers().await;
            });
        }

        // broadcast to websocket new block
        if let Some(rpc) = rpc_server.as_ref() {
            // if we have a getwork server, and that its not from syncing, notify miners
            if broadcast.miners() {
                if let Some(getwork) = rpc.getwork_server() {
                    let getwork = getwork.clone();
                    spawn_task("notify-new-job", async move {
                        let start = Instant::now();
                        if let Err(e) = getwork.get_handler().notify_new_job().await {
                            debug!("Error while notifying new job to miners: {}", e);
                        }

                        histogram!("xelis_notify_new_job_ms").record(start.elapsed().as_millis() as f64);
                    });
                }
            }

            // atm, we always notify websocket clients
            trace!("Notifying websocket clients");
            if should_track_events.contains(&NotifyEvent::NewBlock) {
                // We are not including the transactions in `NewBlock` event to prevent spamming
                match get_block_response(self, &*storage, &block_hash, &Block::new(block, Vec::new()), block_size).await {
                    Ok(response) => {
                        events.entry(NotifyEvent::NewBlock).or_insert_with(Vec::new).push(json!(response));
                    },
                    Err(e) => {
                        debug!("Error while getting block response for websocket: {}", e);
                    }
                };
            }

            let rpc = rpc.clone();
            // don't block mutex/lock more than necessary, we move it in another task
            spawn_task("rpc-notify-events", async move {
                let start = Instant::now();
                for (event, values) in events {
                    for value in values {
                        if let Err(e) = rpc.notify_clients(&event, value).await {
                            debug!("Error while broadcasting event to websocket: {}", e);
                        }
                    }
                }

                histogram!("xelis_new_block_notify_events_ms").record(start.elapsed().as_millis() as f64);
            });
        }

        Ok(())
    }

    // Get block reward based on the type of the block
    // Block shouldn't be orphaned
    pub async fn internal_get_block_reward(&self, past_supply: u64, is_side_block: bool, side_blocks_count: u64, version: BlockVersion) -> Result<u64, BlockchainError> {
        trace!("internal get block reward");
        let block_time_target = get_block_time_target_for_version(version);
        let mut block_reward = get_block_reward(past_supply, block_time_target);
        if is_side_block {
            let side_block_percent = side_block_reward_percentage(side_blocks_count);
            trace!("side block reward: {}%", side_block_percent);

            block_reward = block_reward * side_block_percent / 100;
        }

        Ok(block_reward)
    }

    // Get the block reward for a block
    // This will search all blocks at same height and verify which one are side blocks
    pub async fn get_block_reward<P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + CacheProvider>(&self, provider: &P, hash: &Hash, past_supply: u64, current_topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        let is_side_block = self.is_side_block(provider, hash).await?;
        let mut side_blocks_count = 0;
        if is_side_block {
            // get the block height for this hash
            let height = provider.get_height_for_block_hash(hash).await?;
            let blocks_at_height = provider.get_blocks_at_height(height).await?;
            for block in blocks_at_height {
                if *hash != block && self.is_side_block_internal(provider, &block, current_topoheight).await? {
                    side_blocks_count += 1;
                }
            }
        }

        let version = provider.get_version_for_block_hash(hash).await?;

        self.internal_get_block_reward(past_supply, is_side_block, side_blocks_count, version).await
    }

    // retrieve all txs hashes until height or until genesis block
    // for this we get all tips and recursively retrieve all txs from tips until we reach height
    async fn get_all_txs_until_height<P>(&self, provider: &P, until_height: u64, tips: impl Iterator<Item = Hash>, txs_executed_only: bool, blocks_orphaned_only: bool) -> Result<IndexSet<Hash>, BlockchainError>
    where
        P: DifficultyProvider + ClientProtocolProvider + DagOrderProvider
    {
        trace!("get all txs until height {}", until_height);
        // All transactions hashes found under the stable height
        let mut hashes = IndexSet::new();
        // Current queue of blocks to process
        let mut queue = IndexSet::new();
        // All already processed blocks
        let mut processed = IndexSet::new();
        queue.extend(tips);

        // get last element from queue (order doesn't matter and its faster than moving all elements)
        while let Some(hash) = queue.pop() {
            // Only go through orphaned blocks if required
            if blocks_orphaned_only && provider.is_block_topological_ordered(&hash).await? {
                continue;
            }

            let block = provider.get_block_header_by_hash(&hash).await?;

            // check that the block height is higher than the height passed in param
            if block.get_height() >= until_height {
                // add all txs from block
                for tx in block.get_txs_hashes() {
                    // Check that we don't have it yet
                    if !hashes.contains(tx) {
                        // Then check that it's executed in this block
                        if !txs_executed_only || (txs_executed_only && provider.is_tx_executed_in_block(tx, &hash).await?) {
                            // add it to the list
                            hashes.insert(tx.clone());
                        }
                    }
                }

                // add all tips from block (but check that we didn't already added it)
                for tip in block.get_tips() {
                    if !processed.contains(tip) {
                        processed.insert(tip.clone());
                        queue.insert(tip.clone());
                    }
                }
            }
        }

        Ok(hashes)
    }

    // if a block is not ordered, it's an orphaned block and its transactions are not honoured
    pub async fn is_block_orphaned_for_storage<P: DagOrderProvider>(&self, provider: &P, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("is block {} orphaned", hash);
        Ok(!provider.is_block_topological_ordered(hash).await?)
    }

    pub async fn is_side_block<P: DifficultyProvider + DagOrderProvider + CacheProvider>(&self, provider: &P, hash: &Hash) -> Result<bool, BlockchainError> {
        let chain_cache = provider.chain_cache().await;
        let topoheight = chain_cache.topoheight;
        self.is_side_block_internal(provider, hash, topoheight).await
    }

    // a block is a side block if its ordered and its block height is less than or equal to height of past 8 topographical blocks
    pub async fn is_side_block_internal<P>(&self, provider: &P, hash: &Hash, current_topoheight: TopoHeight) -> Result<bool, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        trace!("is block {} a side block", hash);
        if !provider.is_block_topological_ordered(hash).await? {
            return Ok(false)
        }

        let topoheight = provider.get_topo_height_for_hash(hash).await?;
        // genesis block can't be a side block
        if topoheight == 0 || topoheight > current_topoheight {
            return Ok(false)
        }

        let height = provider.get_height_for_block_hash(hash).await?;

        // verify if there is a block with height higher than this block in past 8 topo blocks
        let mut counter = 0;
        let mut i = topoheight - 1;
        while counter < STABLE_LIMIT && i > 0 {
            let hash = provider.get_hash_at_topo_height(i).await?;
            let previous_height = provider.get_height_for_block_hash(&hash).await?;

            if height <= previous_height {
                return Ok(true)
            }
            counter += 1;
            i -= 1;
        }

        Ok(false)
    }

    // to have stable order: it must be ordered, and be under the stable height limit
    pub async fn has_block_stable_order<P>(&self, provider: &P, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>
    where
        P: DagOrderProvider
    {
        trace!("has block {} stable order at topoheight {}", hash, topoheight);
        if provider.is_block_topological_ordered(hash).await? {
            let block_topo_height = provider.get_topo_height_for_hash(hash).await?;
            return Ok(block_topo_height + STABLE_LIMIT <= topoheight)
        }
        Ok(false)
    }

    // Rewind the chain by removing N blocks from the top
    pub async fn rewind_chain(&self, count: u64, until_stable_height: bool) -> Result<(TopoHeight, Vec<(Hash, Immutable<Transaction>)>), BlockchainError> {
        debug!("rewind chain of {} blocks (stable height: {})", count, until_stable_height);
        let mut storage = self.storage.write().await;
        self.rewind_chain_for_storage(&mut storage, count, until_stable_height).await
    }

    // Rewind the chain by removing N blocks from the top
    pub async fn rewind_chain_for_storage(&self, storage: &mut S, count: u64, stop_at_stable_height: bool) -> Result<(TopoHeight, Vec<(Hash, Immutable<Transaction>)>), BlockchainError> {
        trace!("rewind chain with count = {}", count);

        counter!("xelis_rewind_chain").increment(1);
        histogram!("xelis_rewind_chain_count").record(count as f64);

        let chain_cache = storage.chain_cache().await;
        let current_height = chain_cache.height;
        let current_topoheight = chain_cache.topoheight;
        warn!("Rewind chain with count = {}, height = {}, topoheight = {}", count, current_height, current_topoheight);
        let mut until_topo_height = if stop_at_stable_height {
            chain_cache.stable_topoheight
        } else {
            0
        };

        // iterate through the checkpoints in reverse order
        // to find the newest checkpoint hash
        for hash in self.checkpoints.iter().rev() {
            if storage.is_block_topological_ordered(hash).await? {
                let topo = storage.get_topo_height_for_hash(hash).await?;
                if until_topo_height <= topo {
                    info!("Configured checkpoint {} is at topoheight {}. Prevent to rewind below", hash, topo);
                    until_topo_height = topo;
                    break;
                }
            }
        }

        let start = Instant::now();
        let (new_height, new_topoheight, mut txs) = storage.pop_blocks(current_height, current_topoheight, count, until_topo_height).await?;
        debug!("New topoheight: {} (diff: {})", new_topoheight, current_topoheight - new_topoheight);

        histogram!("xelis_rewind_chain_ms").record(start.elapsed().as_millis() as f64);

        // Clean mempool from old txs if the DAG has been updated
        {
            debug!("lock mempool in write mode for cleaning old TXs");
            let mut mempool = self.mempool.write().await;
            debug!("mempool lock acquired for cleaning old TXs");
            txs.extend(
                mempool.drain()
                    .into_iter()
                    .map(|(hash, tx)| (hash, Immutable::Arc(tx)))
                );
        }

        // Try to add all txs back to mempool if possible
        // We try to prevent lost/to be orphaned
        // We try to add back all txs already in mempool just in case
        let mut orphaned_txs = Vec::new();
        {
            for (hash, mut tx) in txs {
                debug!("Trying to add TX {} to mempool again", hash);
                if let Err(e) = self.add_tx_to_mempool_with_storage_and_hash(storage, tx.make_arc(), Immutable::Owned(hash.clone()), false).await {
                    debug!("TX {} rewinded is not compatible anymore: {}", hash, e);
                    orphaned_txs.push((hash, tx));
                }
            }
        }

        let chain_cache = storage.chain_cache_mut().await?;

        let previous_stable_height = chain_cache.stable_height;
        let previous_stable_topoheight = chain_cache.stable_topoheight;

        chain_cache.height = new_height;
        chain_cache.topoheight = new_topoheight;

        // update stable height if it's allowed
        if !stop_at_stable_height {
            let tips = storage.get_tips().await?;
            let (stable_hash, stable_height) = self.find_common_base::<S, _>(&storage, &tips).await?;
            let stable_topoheight = storage.get_topo_height_for_hash(&stable_hash).await?;

            // if we have a RPC server, propagate the StableHeightChanged if necessary
            if let Some(rpc) = self.rpc.read().await.as_ref() {
                if stable_height != previous_stable_height {
                    if rpc.is_event_tracked(&NotifyEvent::StableHeightChanged).await {
                        let rpc = rpc.clone();
                        spawn_task("rpc-notify-stable-height", async move {
                            let event = json!(StableHeightChangedEvent {
                                previous_stable_height,
                                new_stable_height: stable_height
                            });
    
                            if let Err(e) = rpc.notify_clients(&NotifyEvent::StableHeightChanged, event).await {
                                debug!("Error while broadcasting event StableHeightChanged to websocket: {}", e);
                            }
                        });
                    }
                }

                if stable_topoheight != previous_stable_topoheight {
                    if rpc.is_event_tracked(&NotifyEvent::StableTopoHeightChanged).await {
                        let rpc = rpc.clone();
                        spawn_task("rpc-notify-stable-topoheight", async move {
                            let event = json!(StableTopoHeightChangedEvent {
                                previous_stable_topoheight,
                                new_stable_topoheight: stable_topoheight
                            });
    
                            if let Err(e) = rpc.notify_clients(&NotifyEvent::StableTopoHeightChanged, event).await {
                                debug!("Error while broadcasting event StableTopoHeightChanged to websocket: {}", e);
                            }
                        });
                    }
                }
            }

            // We don't use initialize cache because we already updated half of it by hand above
            let (difficulty, _) = self.get_difficulty_at_tips(&*storage, tips.iter()).await?;
            let chain_cache = storage.chain_cache_mut().await?;

            chain_cache.stable_height = stable_height;
            chain_cache.stable_topoheight = stable_topoheight;
            chain_cache.difficulty = difficulty;
        }

        Ok((new_topoheight, orphaned_txs))
    }

    // Calculate the average block time on the last 50 blocks
    // It will return the target block time if we don't have enough blocks
    // We calculate it by taking the timestamp of the block at topoheight - 50 and the timestamp of the block at topoheight
    // It is the same as computing the average time between the last 50 blocks but much faster
    // Genesis block timestamp isn't take in count for this calculation
    pub async fn get_average_block_time<P>(&self, provider: &P) -> Result<TimestampMillis, BlockchainError>
    where
        P: DifficultyProvider + PrunedTopoheightProvider + DagOrderProvider + CacheProvider
    {
        let chain_cache = provider.chain_cache().await;
        // current topoheight
        let topoheight = chain_cache.topoheight;
        let height = chain_cache.height;

        // we need to get the block hash at topoheight - 50 to compare
        // if topoheight is 0, returns the target as we don't have any block
        // otherwise returns topoheight
        let mut count = if topoheight > CHAIN_AVERAGE_BLOCK_TIME_N {
            CHAIN_AVERAGE_BLOCK_TIME_N
        } else if topoheight <= 1 {
            let version = get_version_at_height(self.get_network(), height);
            return Ok(get_block_time_target_for_version(version));
        } else {
            topoheight - 1
        };

        // check that we are not under the pruned topoheight
        if let Some(pruned_topoheight) = provider.get_pruned_topoheight().await? {
            if topoheight - count < pruned_topoheight {
                count = pruned_topoheight
            }
        }

        let now_hash = provider.get_hash_at_topo_height(topoheight).await?;
        let now_timestamp = provider.get_timestamp_for_block_hash(&now_hash).await?;

        let count_hash = provider.get_hash_at_topo_height(topoheight - count).await?;
        let count_timestamp = provider.get_timestamp_for_block_hash(&count_hash).await?;

        let diff = now_timestamp - count_timestamp;
        Ok(diff / count)
    }

    // Get the average block size over the last N ordered blocks
    pub async fn get_average_block_size<P>(&self, provider: &P) -> Result<usize, BlockchainError>
    where
        P: BlockProvider + PrunedTopoheightProvider + DagOrderProvider + CacheProvider
    {
        // current topoheight
        let chain_cache = provider.chain_cache().await;
        let topoheight = chain_cache.topoheight;

        let mut count = if topoheight >= CHAIN_AVERAGE_BLOCK_TIME_N {
            CHAIN_AVERAGE_BLOCK_TIME_N
        } else {
            topoheight
        };

        // prevent division by zero
        if count == 0 {
            return Ok(0)
        }

        // check that we are not under the pruned topoheight
        if let Some(pruned_topoheight) = provider.get_pruned_topoheight().await? {
            if topoheight - count < pruned_topoheight {
                count = pruned_topoheight
            }
        }

        let mut total = 0;
        for topoheight in topoheight-count..topoheight {
            let block_hash = provider.get_hash_at_topo_height(topoheight).await?;
            let block_size = provider.get_block_size(&block_hash).await?;

            total += block_size;
        }

        Ok(total / count as usize)
    }

    // Calculate the block size EMA at tips weighted by the cumulative difficulty of each branch
    // Weight per cumulative difficulty is required to avoid weak forks/branches to easily skew the EMA
    pub async fn get_blocks_size_ema_at_tips<'a, P>(&self, provider: &P, tips: impl Iterator<Item = &Hash>) -> Result<usize, BlockchainError>
    where
        P: BlockProvider
    {
        trace!("get blocks size ema at tips");

        let mut total = CumulativeDifficulty::zero();
        let mut sum = CumulativeDifficulty::zero();

        for tip in tips {
            let cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(tip).await?;
            let ema = provider.get_block_size_ema(tip).await?;

            total += cumulative_difficulty;
            sum += CumulativeDifficulty::from(ema) * cumulative_difficulty;
        }

        let ema = if total == CumulativeDifficulty::zero() {
            0
        } else {
            let result: u64 = (sum / total).into();
            result as usize
        };

        Ok(ema)
    }

    // Calculate the required base fee, by default its `FEE_PER_KB`
    // fees should get exponential if we are above 10% of the max block size
    // Returns the required base fee and the block size EMA used
    pub async fn get_required_base_fee<P>(&self, provider: &P, tips: impl Iterator<Item = &Hash>) -> Result<(u64, usize), BlockchainError>
    where
        P: BlockProvider
    {
        let ema = self.get_blocks_size_ema_at_tips(provider, tips).await?;
        let base_fee = calculate_required_base_fee(ema);
        Ok((base_fee, ema))
    }

    // Same as `get_required_base_fee` but estimate next blocks by including mempool pending txs
    // Returns the base fee based on current EMA at tips and the predicated one
    async fn predicate_required_base_fee_internal(&self, storage: &S) -> Result<(u64, u64), BlockchainError> {
        let tips = storage.get_tips().await?;
        let initial_ema = self.get_blocks_size_ema_at_tips(&*storage, tips.iter()).await?;
        let mut ema = initial_ema;

        {
            let mut tmp = BlockSizeEma::default(ema);
            let header_size = BlockHeader::estimate_size(tips.len().min(TIPS_LIMIT));
            let mempool = self.mempool.read().await;

            let mut block_size = header_size;

            // Go through all mempool txs and try to fit as many as possible in a block
            // we may have more than one block if we exceed the max block size
            // we don't care about the txs order here, just the size to predicate the EMA
            for (_, tx) in mempool.get_txs() {
                let tx_size = tx.get_size() + HASH_SIZE;
                let new_size = block_size + tx_size;
                if new_size > MAX_BLOCK_SIZE {
                    tmp.add(block_size);

                    // re init the block size with header size only and current tx
                    block_size = header_size + tx_size;

                    let current = tmp.current() as usize;

                    // if the EMA has increased, update it
                    // only expect the EMA to grow
                    if current > ema {
                        ema = current;
                    }
                } else {
                    block_size = new_size;
                }
            }

            let current = tmp.current() as usize;
            if current > ema {
                ema = current;
            }
        }

        let fee_per_kb = calculate_required_base_fee(initial_ema);
        let predicated_fee_per_kb = calculate_required_base_fee(ema);
        debug!(
            "Predicated block size median for next block {} with fee per kb {} (current was {} with fee per kb {})",
            human_bytes::human_bytes(ema as f64),
            predicated_fee_per_kb,
            human_bytes::human_bytes(initial_ema as f64),
            fee_per_kb,
        );

        Ok((fee_per_kb, predicated_fee_per_kb))
    }

    // Same as `get_required_base_fee` but estimate next blocks by including mempool pending txs
    pub async fn predicate_required_base_fee(&self) -> Result<(u64, u64), BlockchainError> {
        let storage = self.storage.read().await;
        self.predicate_required_base_fee_internal(&*storage).await
    }
}

// Calculate the required dynamic base fee based on the block size EMA
// It must handles congestion by raising fees smoothly until we start to
// reach the max block size.
// NOTE: we don't use f64 to prevent any issue that could occurs
// based on the platform/rust version differences
// see `f64::powf`
pub fn calculate_required_base_fee(ema: usize) -> u64 {
    const SCALE: u128 = BlockSizeEma::SCALE;
    const EXP: u32 = 2;
    const K: u128 = 10 * SCALE;

    // scaled usage [0..=SCALE]
    let usage = (ema as u128 * SCALE) / MAX_BLOCK_SIZE as u128;

    // usage^EXP (still scaled^EXP)
    let usage_pow = usage.pow(EXP);

    // scale back: divide by SCALE^(EXP-1)
    let usage_pow_scaled = usage_pow / SCALE.pow(EXP - 1);

    // fee = FEE_PER_KB * (1 + k * usage^exp / SCALE)
    let fee = (FEE_PER_KB as u128 * (SCALE + (K * usage_pow_scaled) / SCALE)) / SCALE;

    (fee as u64).max(FEE_PER_KB)
}

// Esimate the required TX fee extra part
// which is based on the TX outputs, newly generated addresses
// and multsig signatures count
pub async fn estimate_required_tx_fee_extra<P: AccountProvider>(provider: &P, current_topoheight: TopoHeight, tx: &Transaction, block_version: BlockVersion) -> Result<u64, BlockchainError> {
    let mut processed_keys = HashSet::new();
    let mut transfers_len = 0;
    if let TransactionType::Transfers(transfers) = tx.get_data() {
        for transfer in transfers {
            if !processed_keys.contains(transfer.get_destination()) && !provider.is_account_registered_for_topoheight(transfer.get_destination(), current_topoheight).await? {
                debug!("Account {} is not registered for topoheight {}", transfer.get_destination().as_address(provider.is_mainnet()), current_topoheight);
                processed_keys.insert(transfer.get_destination());
            }
        }

        transfers_len = transfers.len();
    }

    let outputs = if block_version >= BlockVersion::V3 {
        tx.get_outputs_count()
    } else {
        transfers_len
    };

    Ok(calculate_tx_fee_extra(outputs, processed_keys.len(), tx.get_multisig_count()))
}

// Estimate the TX fee per kB by calculating and sub the fee extra part
// NOTE: tx size is in bytes, not kB
pub async fn estimate_tx_fee_per_kb<P: AccountProvider>(provider: &P, current_topoheight: TopoHeight, tx: &Transaction, tx_size: usize, block_version: BlockVersion) -> Result<(u64, u64), BlockchainError> {
    let fee_extra = estimate_required_tx_fee_extra(provider, current_topoheight, tx, block_version).await?;
    let fee = tx.get_fee()
        .checked_sub(fee_extra)
        .ok_or(BlockchainError::InvalidTxFee(fee_extra, tx.get_fee()))?;

    let fee_limit = tx.get_fee_limit()
        .checked_sub(fee_extra)
        .ok_or(BlockchainError::InvalidTxFee(fee_extra, tx.get_fee_limit()))?;

    // We round it up to the next kB because
    // the verification part is doing it
    let tx_size_rounded = tx_kb_size_rounded(tx_size) as u64;
    let fee_per_kb = fee / tx_size_rounded;
    let fee_limit_per_kb = fee_limit / tx_size_rounded;

    Ok((fee_per_kb, fee_limit_per_kb))
}

// Count how many kB is counted for TX size in bytes
// NOTE: Even if a kB is not fully consumed, it is counted as is
#[inline(always)]
pub const fn tx_kb_size_rounded(bytes: usize) -> usize {
    (bytes + (BYTES_PER_KB - 1)) / BYTES_PER_KB
}

// Estimate the required final fee for TX
// This is based on the outputs/transfers in the TX, but also
// based on the newly generated addresses
// Multisig signatures also increase the extra fee due to more computation being required
// This returns one final (total) fee required for a TX
pub async fn estimate_required_tx_fees<P: AccountProvider>(provider: &P, current_topoheight: TopoHeight, tx: &Transaction, tx_size: usize, base_fee: u64, block_version: BlockVersion) -> Result<u64, BlockchainError> {
    let fee_extra = estimate_required_tx_fee_extra(provider, current_topoheight, tx, block_version).await?;
    Ok(calculate_tx_fee_per_kb(base_fee, tx_size) + fee_extra)
}

// Get the block reward for a side block based on how many side blocks exists at same height
pub fn side_block_reward_percentage(side_blocks: u64) -> u64 {
    let mut side_block_percent = SIDE_BLOCK_REWARD_PERCENT;
    if side_blocks > 0 {
        if side_blocks < SIDE_BLOCK_REWARD_MAX_BLOCKS {
            side_block_percent = SIDE_BLOCK_REWARD_PERCENT / (side_blocks * 2);
        } else {
            // If we have more than 3 side blocks at same height
            // we reduce the reward to 5%
            side_block_percent = SIDE_BLOCK_REWARD_MIN_PERCENT;
        }
    }

    side_block_percent
}

// Calculate the block reward based on the emitted supply
pub fn get_block_reward(supply: u64, block_time_target: u64) -> u64 {
    // Prevent any overflow
    if supply >= MAXIMUM_SUPPLY {
        // Max supply reached, do we want to generate small fixed amount of coins? 
        return 0
    }

    let base_reward = (MAXIMUM_SUPPLY - supply) >> EMISSION_SPEED_FACTOR;
    base_reward * block_time_target / MILLIS_PER_SECOND / 180
}

// Returns the fee percentage for a block at a given height
pub fn get_block_dev_fee(height: u64) -> u64 {
    let mut percentage = 0;
    for threshold in DEV_FEES.iter() {
        if height >= threshold.height {
            percentage = threshold.fee_percentage;
        }
    }

    percentage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reward_side_block_percentage() {
        assert_eq!(side_block_reward_percentage(0), SIDE_BLOCK_REWARD_PERCENT);
        assert_eq!(side_block_reward_percentage(1), SIDE_BLOCK_REWARD_PERCENT / 2);
        assert_eq!(side_block_reward_percentage(2), SIDE_BLOCK_REWARD_PERCENT / 4);
        assert_eq!(side_block_reward_percentage(3), SIDE_BLOCK_REWARD_MIN_PERCENT);
    }

    #[test]
    fn test_block_dev_fee() {
        assert_eq!(get_block_dev_fee(0), 10);
        assert_eq!(get_block_dev_fee(1), 10);

        // ~ current height
        assert_eq!(get_block_dev_fee(55_000), 10);

        // End of the first threshold, we pass to 5%
        assert_eq!(get_block_dev_fee(3_250_000), 5);

        assert_eq!(get_block_dev_fee(DEV_FEES[0].height), 10);
        assert_eq!(get_block_dev_fee(DEV_FEES[1].height), 5);
        assert_eq!(get_block_dev_fee(DEV_FEES[1].height + 1), 5);
    }

    #[test]
    fn test_base_fee() {
        // EMA block size below 1024 bytes is the minimum fee
        assert_eq!(calculate_required_base_fee(0), FEE_PER_KB);
        assert_eq!(calculate_required_base_fee(1024), FEE_PER_KB);

        // Max block size EMA is up to x11 the required base fee
        assert_eq!(calculate_required_base_fee(MAX_BLOCK_SIZE), FEE_PER_KB * 11);
    }
}