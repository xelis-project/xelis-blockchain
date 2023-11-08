use anyhow::Error;
use lru::LruCache;
use serde_json::{Value, json};
use xelis_common::{
    config::{XELIS_ASSET, COIN_DECIMALS},
    crypto::{key::PublicKey, hash::{Hashable, Hash, HASH_SIZE}},
    difficulty::check_difficulty,
    transaction::{Transaction, TransactionType, EXTRA_DATA_LIMIT_SIZE},
    utils::{get_current_timestamp, format_xelis, get_current_time},
    block::{Block, BlockHeader, EXTRA_NONCE_SIZE, Difficulty},
    immutable::Immutable,
    serializer::Serializer,
    account::VersionedBalance,
    api::{
        daemon::{
            NotifyEvent,
            BlockOrderedEvent,
            TransactionExecutedEvent,
            BlockType,
            StableHeightChangedEvent,
            TransactionResponse
        },
        DataHash
    },
    network::Network,
    asset::AssetData
};
use crate::{
    config::{
        DEFAULT_P2P_BIND_ADDRESS, P2P_DEFAULT_MAX_PEERS, DEFAULT_RPC_BIND_ADDRESS, DEFAULT_CACHE_SIZE, MAX_BLOCK_SIZE,
        EMISSION_SPEED_FACTOR, MAX_SUPPLY, DEV_FEE_PERCENT, GENESIS_BLOCK, TIPS_LIMIT, TIMESTAMP_IN_FUTURE_LIMIT,
        STABLE_LIMIT, GENESIS_BLOCK_HASH, MINIMUM_DIFFICULTY, GENESIS_BLOCK_DIFFICULTY, SIDE_BLOCK_REWARD_PERCENT,
        DEV_PUBLIC_KEY, BLOCK_TIME, PRUNE_SAFETY_LIMIT, BLOCK_TIME_MILLIS,
    },
    core::difficulty::calculate_difficulty,
    p2p::P2pServer,
    rpc::{
        rpc::{
            get_block_response_for_hash, get_block_type_for_block
        },
        DaemonRpcServer, SharedDaemonRpcServer
    }
};
use super::storage::{Storage, DifficultyProvider};
use std::{sync::atomic::{Ordering, AtomicU64}, collections::hash_map::Entry, time::{Duration, Instant}, borrow::Cow};
use std::collections::{HashMap, HashSet};
use async_recursion::async_recursion;
use tokio::{time::interval, sync::{Mutex, RwLock}};
use log::{info, error, debug, warn, trace};
use std::net::SocketAddr;
use std::sync::Arc;
use rand::Rng;

use super::blockdag;
use super::error::BlockchainError;
use super::mempool::Mempool;

#[derive(Debug, clap::StructOpt)]
pub struct Config {
    /// Optional node tag
    #[clap(short, long)]
    pub tag: Option<String>,
    /// P2p bind address to listen for incoming connections
    #[clap(short, long, default_value_t = String::from(DEFAULT_P2P_BIND_ADDRESS))]
    pub p2p_bind_address: String,
    /// Number of maximums peers allowed
    #[clap(short, long, default_value_t = P2P_DEFAULT_MAX_PEERS)]
    pub max_peers: usize,
    /// Rpc bind address to listen for HTTP requests
    #[clap(short, long, default_value_t = String::from(DEFAULT_RPC_BIND_ADDRESS))]
    pub rpc_bind_address: String,
    /// Add a priority node to connect when P2p is started
    /// A priority node is connected only one time
    #[clap(short = 'o', long)]
    pub priority_nodes: Vec<String>,
    /// An exclusive node is connected and its connection is maintained in case of disconnect
    /// it also replaces seed nodes
    #[clap(short, long)]
    pub exclusive_nodes: Vec<String>,
    /// Set dir path for blockchain storage
    #[clap(short = 's', long)]
    pub dir_path: Option<String>,
    /// Set LRUCache size (0 = disabled)
    #[clap(short, long, default_value_t = DEFAULT_CACHE_SIZE)]
    pub cache_size: usize,
    /// Disable GetWork Server (WebSocket for miners)
    #[clap(short = 'g', long)]
    pub disable_getwork_server: bool,
    /// Enable the simulator (skip PoW verification, generate a new block for every BLOCK_TIME)
    #[clap(long)]
    pub simulator: bool,
    /// Disable the p2p connections
    #[clap(long)]
    pub disable_p2p_server: bool,
    /// Enable the auto prune mode and prune the chain
    /// at each new block by keeping at least N blocks
    /// before the top.
    #[clap(long)]
    pub auto_prune_keep_n_blocks: Option<u64>,
    /// Sync a bootstrapped chain if your local copy is outdated.
    /// It will not store any blocks / TXs and will not verify the history locally.
    /// Use it with extreme cautions and trusted nodes to have a valid bootstrapped chain
    #[clap(long)]
    pub allow_fast_sync: bool
}

pub struct Blockchain<S: Storage> {
    height: AtomicU64, // current block height
    topoheight: AtomicU64, // current topo height
    stable_height: AtomicU64, // current stable height
    mempool: RwLock<Mempool>, // mempool to retrieve/add all txs
    storage: RwLock<S>, // storage to retrieve/add blocks
    p2p: RwLock<Option<Arc<P2pServer<S>>>>, // P2p module
    rpc: RwLock<Option<SharedDaemonRpcServer<S>>>, // Rpc module
    // current difficulty at tips
    // its used as cache to display current network hashrate
    difficulty: AtomicU64,
    // used to skip PoW verification
    simulator: bool,
    // current network type on which one we're using/connected to
    network: Network,
    // this cache is used to avoid to recompute the common base for each block and is mandatory
    // key is (tip hash, tip height) while value is (base hash, base height)
    tip_base_cache: Mutex<LruCache<(Hash, u64), (Hash, u64)>>,
    // tip work score is used to determine the best tip based on a block, tip base ands a base height
    tip_work_score_cache: Mutex<LruCache<(Hash, Hash, u64), (HashSet<Hash>, Difficulty)>>,
    full_order_cache: Mutex<LruCache<(Hash, Hash, u64), Vec<Hash>>>,
    // auto prune mode if enabled, will delete all blocks every N and keep only N top blocks (topoheight based)
    auto_prune_keep_n_blocks: Option<u64>,
    // allow fast syncing (only balances / assets / Smart Contracts changes)
    // without syncing the history
    allow_fast_sync_mode: bool
}

impl<S: Storage> Blockchain<S> {
    pub async fn new(config: Config, network: Network, storage: S) -> Result<Arc<Self>, Error> {
        if config.simulator && network != Network::Dev {
            error!("Impossible to enable simulator mode except in dev network!");
            return Err(BlockchainError::InvalidNetwork.into())
        }

        if let Some(keep_only) = config.auto_prune_keep_n_blocks {
            if keep_only < PRUNE_SAFETY_LIMIT {
                error!("Auto prune mode should keep at least 80 blocks");
                return Err(BlockchainError::AutoPruneMode.into())
            }
        }

        let on_disk = storage.has_blocks();
        let (height, topoheight) = if on_disk {
            info!("Reading last metadata available...");
            let height = storage.get_top_height()?;
            let topoheight = storage.get_top_topoheight()?;

            (height, topoheight)
        } else { (0, 0) };

        info!("Initializing chain...");
        let blockchain = Self {
            height: AtomicU64::new(height),
            topoheight: AtomicU64::new(topoheight),
            stable_height: AtomicU64::new(0),
            mempool: RwLock::new(Mempool::new()),
            storage: RwLock::new(storage),
            p2p: RwLock::new(None),
            rpc: RwLock::new(None),
            difficulty: AtomicU64::new(GENESIS_BLOCK_DIFFICULTY),
            simulator: config.simulator,
            network,
            tip_base_cache: Mutex::new(LruCache::new(1024)),
            tip_work_score_cache: Mutex::new(LruCache::new(1024)),
            full_order_cache: Mutex::new(LruCache::new(1024)),
            auto_prune_keep_n_blocks: config.auto_prune_keep_n_blocks,
            allow_fast_sync_mode: config.allow_fast_sync
        };

        // include genesis block
        if !on_disk {
            blockchain.create_genesis_block().await?;
        } else {
            debug!("Retrieving tips for computing current difficulty");
            let storage = blockchain.get_storage().read().await;
            let tips_set = storage.get_tips().await?;
            let mut tips = Vec::with_capacity(tips_set.len());
            for hash in tips_set {
                tips.push(hash);
            }
    
            let difficulty = blockchain.get_difficulty_at_tips(&*storage, &tips).await?;
            blockchain.difficulty.store(difficulty, Ordering::SeqCst);
        }

        // now compute the stable height
        {
            debug!("Retrieving tips for computing current stable height");
            let storage = blockchain.get_storage().read().await;
            let tips = storage.get_tips().await?;
            let (_, stable_height) = blockchain.find_common_base(&storage, &tips).await?;
            blockchain.stable_height.store(stable_height, Ordering::SeqCst);
        }

        let arc = Arc::new(blockchain);
        // create P2P Server
        if !config.disable_p2p_server && arc.network != Network::Dev  {
            info!("Starting P2p server...");
            // setup exclusive nodes
            let mut exclusive_nodes: Vec<SocketAddr> = Vec::with_capacity(config.exclusive_nodes.len());
            for peer in config.exclusive_nodes {
                let addr: SocketAddr = match peer.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("Error while parsing priority node address: {}", e);
                        continue;
                    }
                };
                exclusive_nodes.push(addr);
            }
            match P2pServer::new(config.tag, config.max_peers, config.p2p_bind_address, Arc::clone(&arc), exclusive_nodes.is_empty(), exclusive_nodes) {
                Ok(p2p) => {
                    // connect to priority nodes
                    for addr in config.priority_nodes {
                        let addr: SocketAddr = match addr.parse() {
                            Ok(addr) => addr,
                            Err(e) => {
                                error!("Error while parsing priority node address: {}", e);
                                continue;
                            }
                        };
                        info!("Trying to connect to priority node: {}", addr);
                        p2p.try_to_connect_to_peer(addr, true).await;
                    }
                    *arc.p2p.write().await = Some(p2p);
                },
                Err(e) => error!("Error while starting P2p server: {}", e)
            };
        }

        // create RPC Server
        {
            info!("Starting RPC server...");
            match DaemonRpcServer::new(config.rpc_bind_address, Arc::clone(&arc), config.disable_getwork_server).await {
                Ok(server) => *arc.rpc.write().await = Some(server),
                Err(e) => error!("Error while starting RPC server: {}", e)
            };
        }

        if arc.simulator {
            warn!("Simulator mode enabled!");
            let zelf = Arc::clone(&arc);
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(BLOCK_TIME));
                loop {
                    interval.tick().await;
                    info!("Adding new simulated block...");
                    if let Err(e) = zelf.mine_block(&DEV_PUBLIC_KEY).await {
                        error!("Simulator error: {}", e);
                    }
                }
            });
        }

        Ok(arc)
    }

    pub async fn stop(&self) {
        info!("Stopping modules...");
        let mut p2p = self.p2p.write().await;
        if let Some(p2p) = p2p.take() {
            p2p.stop().await;
        }

        let mut rpc = self.rpc.write().await;
        if let Some(rpc) = rpc.take() {
            rpc.stop().await;
        }
        info!("All modules are now stopped!");
    }

    pub async fn reload_from_disk(&self) -> Result<(), BlockchainError> {
        trace!("Reloading chain from disk");
        let storage = self.storage.read().await;
        let topoheight = storage.get_top_topoheight()?;
        let height = storage.get_top_height()?;
        self.topoheight.store(topoheight, Ordering::SeqCst);
        self.height.store(height, Ordering::SeqCst);

        let tips = storage.get_tips().await?;
        let (_, stable_height) = self.find_common_base(&*storage, &tips).await?;
        self.stable_height.store(stable_height, Ordering::SeqCst);

        let difficulty = self.get_difficulty_at_tips(&*storage, &tips.into_iter().collect()).await?;
        self.difficulty.store(difficulty, Ordering::SeqCst);

        // TXs in mempool may be outdated, clear them as they will be asked later again
        debug!("locking mempool for cleaning");
        let mut mempool = self.mempool.write().await;
        debug!("Clearing mempool");
        mempool.clear();

        Ok(())
    }

    // function to include the genesis block and register the public dev key.
    async fn create_genesis_block(&self) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;

        // register XELIS asset
        debug!("Registering XELIS asset: {} at topoheight 0", XELIS_ASSET);
        storage.add_asset(&XELIS_ASSET, AssetData::new(0, COIN_DECIMALS)).await?;

        let genesis_block = if GENESIS_BLOCK.len() != 0 {
            info!("De-serializing genesis block...");
            let genesis = Block::from_hex(GENESIS_BLOCK.to_owned())?;
            if *genesis.get_miner() != *DEV_PUBLIC_KEY {
                return Err(BlockchainError::GenesisBlockMiner)
            }

            let expected_hash = genesis.hash();
            if *GENESIS_BLOCK_HASH != expected_hash {
                error!("Genesis block hash is invalid! Expected: {}, got: {}", expected_hash, *GENESIS_BLOCK_HASH);
                return Err(BlockchainError::InvalidGenesisHash)
            }

            debug!("Adding genesis block '{}' to chain", *GENESIS_BLOCK_HASH);
            genesis
        } else {
            error!("No genesis block found!");
            info!("Generating a new genesis block...");
            let header = BlockHeader::new(0, 0, get_current_timestamp(), Vec::new(), [0u8; EXTRA_NONCE_SIZE], DEV_PUBLIC_KEY.clone(), Vec::new());
            let block = Block::new(Immutable::Owned(header), Vec::new());
            info!("Genesis generated: {}", block.to_hex());
            block
        };

        // hardcode genesis block topoheight
        storage.set_topo_height_for_block(&genesis_block.hash(), 0).await?;
        storage.set_top_height(0)?;

        self.add_new_block_for_storage(&mut storage, genesis_block, false, false).await?;

        Ok(())
    }

    // mine a block for current difficulty
    pub async fn mine_block(self: &Arc<Self>, key: &PublicKey) -> Result<(), BlockchainError> {
        let (mut header, difficulty) = {
            let storage = self.storage.read().await;
            let block = self.get_block_template_for_storage(&storage, key.clone()).await?;
            let difficulty = self.get_difficulty_at_tips(&*storage, &block.get_tips()).await?;
            (block, difficulty)
        };
        let mut hash = header.hash();
        let mut current_height = self.get_height();
        while !self.simulator && !check_difficulty(&hash, difficulty)? {
            if self.get_height() != current_height {
                current_height = self.get_height();
                header = self.get_block_template(key.clone()).await?;
            }
            header.nonce += 1;
            header.timestamp = get_current_timestamp();
            hash = header.hash();
        }

        let block = self.build_block_from_header(Immutable::Owned(header)).await?;
        let zelf = Arc::clone(self);
        let block_height = block.get_height();
        zelf.add_new_block(block, true, true).await?;
        info!("Mined a new block {} at height {}", hash, block_height);
        Ok(())
    }

    // check if user has accepted to do fast sync mode
    pub fn is_fast_sync_mode_allowed(&self) -> bool {
        self.allow_fast_sync_mode
    }

    pub async fn prune_until_topoheight(&self, topoheight: u64) -> Result<u64, BlockchainError> {
        let mut storage = self.storage.write().await;
        self.prune_until_topoheight_for_storage(topoheight, &mut storage).await
    }

    // delete all blocks / versioned balances / txs until topoheight in param
    // for this, we have to locate the nearest Sync block for DAG under the limit topoheight
    // and then delete all blocks before it
    // keep a marge of PRUNE_SAFETY_LIMIT
    pub async fn prune_until_topoheight_for_storage(&self, topoheight: u64, storage: &mut S) -> Result<u64, BlockchainError> {
        if topoheight == 0 {
            return Err(BlockchainError::PruneZero)
        }

        let current_topoheight = self.get_topo_height();
        if topoheight >= current_topoheight || current_topoheight - topoheight < PRUNE_SAFETY_LIMIT {
            return Err(BlockchainError::PruneHeightTooHigh)
        }

        let last_pruned_topoheight = storage.get_pruned_topoheight()?.unwrap_or(0);
        if topoheight < last_pruned_topoheight {
            return Err(BlockchainError::PruneLowerThanLastPruned)
        }

        // find new stable point based on a sync block under the limit topoheight
        let located_sync_topoheight = self.locate_nearest_sync_block_for_topoheight(&storage, topoheight, self.get_height()).await?;
        debug!("Located sync topoheight found: {}", located_sync_topoheight);
        
        if located_sync_topoheight > last_pruned_topoheight {
            let assets = storage.get_assets().await?;
            // create snapshots of balances to located_sync_topoheight
            storage.create_snapshot_balances_at_topoheight(&assets, located_sync_topoheight).await?;
            storage.create_snapshot_nonces_at_topoheight(located_sync_topoheight).await?;

            // delete all blocks until the new topoheight
            for topoheight in last_pruned_topoheight..located_sync_topoheight {
                trace!("Pruning block at topoheight {}", topoheight);
                // delete block
                let _ = storage.delete_block_at_topoheight(topoheight).await?;

                // delete balances for all assets
                for asset in &assets {
                    storage.delete_versioned_balances_for_asset_at_topoheight(asset, topoheight).await?;
                }

                // delete nonces versions
                storage.delete_versioned_nonces_at_topoheight(topoheight).await?;
            }
            storage.set_pruned_topoheight(located_sync_topoheight)?;
            Ok(located_sync_topoheight)
        } else {
            debug!("located_sync_topoheight <= topoheight, no pruning needed");
            Ok(last_pruned_topoheight)
        }
    }

    // determine the topoheight of the nearest sync block until limit topoheight
    pub async fn locate_nearest_sync_block_for_topoheight(&self, storage: &S, mut topoheight: u64, current_height: u64) -> Result<u64, BlockchainError> {
        while topoheight > 0 {
            let block_hash = storage.get_hash_at_topo_height(topoheight).await?;
            if self.is_sync_block_at_height(storage, &block_hash, current_height).await? {
                let topoheight = storage.get_topo_height_for_hash(&block_hash).await?;
                return Ok(topoheight)
            }

            topoheight -= 1;
        }

        // genesis block is always a sync block
        Ok(0)
    }

    // returns the highest (unstable) height on the chain
    pub fn get_height(&self) -> u64 {
        self.height.load(Ordering::Acquire)
    }

    // returns the highest topological height
    pub fn get_topo_height(&self) -> u64 {
        self.topoheight.load(Ordering::Acquire)
    }

    pub fn get_stable_height(&self) -> u64 {
        self.stable_height.load(Ordering::Acquire)
    }

    pub fn get_network(&self) -> &Network {
        &self.network
    }

    pub async fn get_supply(&self) -> Result<u64, BlockchainError> {
        self.storage.read().await.get_supply_at_topo_height(self.get_topo_height()).await
    }

    pub async fn get_mempool_size(&self) -> usize {
        self.mempool.read().await.size()
    }

    pub async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_top_block_hash_for_storage(&storage).await
    }

    // because we are in chain, we already now the highest topoheight
    // we call the get_hash_at_topo_height instead of get_top_block_hash to avoid reading value
    // that we already know
    pub async fn get_top_block_hash_for_storage(&self, storage: &S) -> Result<Hash, BlockchainError> {
        storage.get_hash_at_topo_height(self.get_topo_height()).await
    }

    pub async fn has_block(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        let storage = self.storage.read().await;
        storage.has_block(hash).await
    }

    pub async fn is_sync_block(&self, storage: &S, hash: &Hash) -> Result<bool, BlockchainError> {
        let current_height = self.get_height();
        self.is_sync_block_at_height(storage, hash, current_height).await
    }

    async fn is_sync_block_at_height(&self, storage: &S, hash: &Hash, height: u64) -> Result<bool, BlockchainError> {
        trace!("is sync block {} at height {}", hash, height);
        let block_height = storage.get_height_for_block_hash(hash).await?;
        if block_height == 0 { // genesis block is a sync block
            return Ok(true)
        }

        // block must be ordered and in stable height
        if block_height + STABLE_LIMIT > height || !storage.is_block_topological_ordered(hash).await {
            return Ok(false)
        }

        // if block is alone at its height, it is a sync block
        let tips_at_height = storage.get_blocks_at_height(block_height).await?;
        if tips_at_height.len() == 1 {
            return Ok(true)
        }

        // if block is not alone at its height and they are ordered (not orphaned), it can't be a sync block
        let mut blocks_in_main_chain = 0;
        for hash in tips_at_height {
            if storage.is_block_topological_ordered(&hash).await {
                blocks_in_main_chain += 1;
                if blocks_in_main_chain > 1 {
                    return Ok(false)
                }
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
            let blocks = storage.get_blocks_at_height(i).await?;
            pre_blocks.extend(blocks);
            i -= 1;
        }

        let sync_block_cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(hash).await?;
        // if potential sync block has lower cumulative difficulty than one of past blocks, it is not a sync block
        for hash in pre_blocks {
            let cumulative_difficulty = storage.get_cumulative_difficulty_for_block_hash(&hash).await?;
            if cumulative_difficulty >= sync_block_cumulative_difficulty {
                return Ok(false)
            }
        }

        Ok(true)
    }

    #[async_recursion]
    async fn find_tip_base(&self, storage: &S, hash: &Hash, height: u64, pruned_topoheight: u64) -> Result<(Hash, u64), BlockchainError> {
        if pruned_topoheight > 0 && storage.is_block_topological_ordered(hash).await {
            let topoheight = storage.get_topo_height_for_hash(hash).await?;
            // Node is pruned, we only prune chain to stable height so we can return the hash
            if topoheight <= pruned_topoheight {
                debug!("Node is pruned, returns {} at {} as stable tip base", hash, height);
                return Ok((hash.clone(), height))
            }
        }

        let (tips, tips_count) = {
            // first, check if we have it in cache
            let mut cache = self.tip_base_cache.lock().await;
            if let Some((base_hash, base_height)) = cache.get(&(hash.clone(), height)) {
                trace!("Tip Base for {} at height {} found in cache: {} for height {}", hash, height, base_hash, base_height);
                return Ok((base_hash.clone(), *base_height))
            }

            let tips = storage.get_past_blocks_for_block_hash(hash).await?;
            let tips_count = tips.len();
            if tips_count == 0 { // only genesis block can have 0 tips saved
                // save in cache
                cache.put((hash.clone(), height), (hash.clone(), 0));
                return Ok((hash.clone(), 0))
            }
            (tips, tips_count)
        };

        let mut bases = Vec::with_capacity(tips_count);
        for hash in tips.iter() {
            if pruned_topoheight > 0 && storage.is_block_topological_ordered(hash).await {
                let topoheight = storage.get_topo_height_for_hash(hash).await?;
                // Node is pruned, we only prune chain to stable height so we can return the hash
                if topoheight <= pruned_topoheight {
                    let block_height = storage.get_height_for_block_hash(hash).await?;
                    debug!("Node is pruned, returns tip {} at {} as stable tip base", hash, block_height);
                    return Ok((hash.clone(), block_height))
                }
            }
            // if block is sync, it is a tip base
            if self.is_sync_block_at_height(storage, hash, height).await? {
                let block_height = storage.get_height_for_block_hash(hash).await?;
                // save in cache (lock each time to avoid deadlocks)
                let mut cache = self.tip_base_cache.lock().await;
                cache.put((hash.clone(), height), (hash.clone(), block_height));

                return Ok((hash.clone(), block_height))
            }

            // if block is not sync, we need to find its tip base too
            bases.push(self.find_tip_base(storage, hash, height, pruned_topoheight).await?);
        }

        if bases.is_empty() {
            error!("Tip base for {} at height {} not found", hash, height);
            return Err(BlockchainError::ExpectedTips)
        }

        // now we sort descending by height and return the last element deleted
        bases.sort_by(|(_, a), (_, b)| b.cmp(a));
        debug_assert!(bases[0].1 >= bases[bases.len() - 1].1);

        let (base_hash, base_height) = bases.remove(bases.len() - 1);
        // save in cache
        let mut cache = self.tip_base_cache.lock().await;
        cache.put((hash.clone(), height), (base_hash.clone(), base_height));
        trace!("Tip Base for {} at height {} found: {} for height {}", hash, height, base_hash, base_height);

        Ok((base_hash, base_height))
    }

    // find the common base (block hash and block height) of all tips
    pub async fn find_common_base<'a, I: IntoIterator<Item = &'a Hash> + Copy>(&self, storage: &S, tips: I) -> Result<(Hash, u64), BlockchainError> {
        debug!("Searching for common base for tips {}", tips.into_iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "));
        let mut best_height = 0;
        // first, we check the best (highest) height of all tips
        for hash in tips.into_iter() {
            let height = storage.get_height_for_block_hash(hash).await?;
            if height > best_height {
                best_height = height;
            }
        }

        let pruned_topoheight = storage.get_pruned_topoheight()?.unwrap_or(0);
        let mut bases = Vec::new();
        for hash in tips.into_iter() {
            bases.push(self.find_tip_base(storage, hash, best_height, pruned_topoheight).await?);
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
        Ok((base_hash, base_height))
    }

    #[async_recursion] // TODO no recursion
    async fn build_reachability_recursive(&self, storage: &S, set: &mut HashSet<Hash>, hash: Hash, level: u64) -> Result<(), BlockchainError> {
        if level >= 2 * STABLE_LIMIT {
            trace!("Level limit reached, adding {}", hash);
            set.insert(hash);
        } else {
            trace!("Level {} reached with hash {}", level, hash);
            let tips = storage.get_past_blocks_for_block_hash(&hash).await?;
            set.insert(hash);
            for past_hash in tips.iter() {
                if !set.contains(past_hash) {
                    self.build_reachability_recursive(storage, set, past_hash.clone(), level + 1).await?;
                }
            }
        }

        Ok(())
    }

    // this function check that a TIP cannot be refered as past block in another TIP
    async fn verify_non_reachability(&self, storage: &S, block: &BlockHeader) -> Result<bool, BlockchainError> {
        let tips = block.get_tips();
        let tips_count = tips.len();
        let mut reach = Vec::with_capacity(tips_count);
        for hash in block.get_tips() {
            let mut set = HashSet::new();
            // TODO no clone
            self.build_reachability_recursive(storage, &mut set, hash.clone(), 0).await?;
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

    #[async_recursion] // TODO no recursion
    async fn calculate_distance_from_mainchain_recursive(&self, storage: &S, set: &mut HashSet<u64>, hash: &Hash) -> Result<(), BlockchainError> {
        let tips = storage.get_past_blocks_for_block_hash(hash).await?;
        for hash in tips.iter() {
            if storage.is_block_topological_ordered(hash).await {
                set.insert(storage.get_height_for_block_hash(hash).await?);
            } else {
                self.calculate_distance_from_mainchain_recursive(storage, set, hash).await?;
            }
        }
        Ok(())
    }

    async fn calculate_distance_from_mainchain(&self, storage: &S, hash: &Hash) -> Result<u64, BlockchainError> {
        if storage.is_block_topological_ordered(hash).await {
            let height = storage.get_height_for_block_hash(hash).await?;
            debug!("calculate_distance: Block {} is at height {}", hash, height);
            return Ok(height)
        }
        debug!("calculate_distance: Block {} is not ordered, calculate distance from mainchain", hash);
        let mut set = HashSet::new(); // replace by a Vec and sort + remove first ?
        self.calculate_distance_from_mainchain_recursive(storage, &mut set, hash).await?;

        let mut lowest_height = u64::max_value();
        for height in &set {
            if lowest_height > *height {
                lowest_height = *height;
            }
        }

        debug!("calculate_distance: lowest height found is {} on {} elements", lowest_height, set.len());
        Ok(lowest_height)
    }

    #[async_recursion] // TODO no recursion
    async fn find_tip_work_score_internal<'a>(&self, storage: &S, map: &mut HashMap<Hash, Difficulty>, hash: &'a Hash, base_topoheight: u64, base_height: u64) -> Result<(), BlockchainError> {
        let tips = storage.get_past_blocks_for_block_hash(hash).await?;
        for hash in tips.iter() {
            if !map.contains_key(hash) {
                let is_ordered = storage.is_block_topological_ordered(hash).await;
                if !is_ordered || (is_ordered && storage.get_topo_height_for_hash(hash).await? >= base_topoheight) {
                    self.find_tip_work_score_internal(storage, map, hash, base_topoheight, base_height).await?;
                }
            }
        }

        map.insert(hash.clone(), storage.get_difficulty_for_block_hash(hash).await?);

        Ok(())
    }

    // find the sum of work done
    async fn find_tip_work_score(&self, storage: &S, hash: &Hash, base: &Hash, base_height: u64) -> Result<(HashSet<Hash>, Difficulty), BlockchainError> {
        let mut cache = self.tip_work_score_cache.lock().await;
        if let Some(value) = cache.get(&(hash.clone(), base.clone(), base_height)) {
            trace!("Found tip work score in cache: set [{}], height: {}", value.0.iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "), value.1);
            return Ok(value.clone())
        }

        let block = storage.get_block_header_by_hash(hash).await?;
        let mut map: HashMap<Hash, Difficulty> = HashMap::new();
        let base_topoheight = storage.get_topo_height_for_hash(base).await?;
        for hash in block.get_tips() {
            if !map.contains_key(hash) {
                let is_ordered = storage.is_block_topological_ordered(hash).await;
                if !is_ordered || (is_ordered && storage.get_topo_height_for_hash(hash).await? >= base_topoheight) {
                    self.find_tip_work_score_internal(storage, &mut map, hash, base_topoheight, base_height).await?;
                }
            }
        }

        if base != hash {
            map.insert(base.clone(), storage.get_cumulative_difficulty_for_block_hash(base).await?);
        }
        map.insert(hash.clone(), storage.get_difficulty_for_block_hash(hash).await?);

        let mut set = HashSet::with_capacity(map.len());
        let mut score = 0;
        for (hash, value) in map {
            set.insert(hash);
            score += value;
        }

        // save this result in cache
        cache.put((hash.clone(), base.clone(), base_height), (set.clone(), score));

        Ok((set, score))
    }

    async fn find_best_tip<'a>(&self, storage: &S, tips: &'a HashSet<Hash>, base: &Hash, base_height: u64) -> Result<&'a Hash, BlockchainError> {
        if tips.len() == 0 {
            return Err(BlockchainError::ExpectedTips)
        }

        let mut scores = Vec::with_capacity(tips.len());
        for hash in tips {
            let (_, cumulative_difficulty) = self.find_tip_work_score(storage, hash, base, base_height).await?;
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
    #[async_recursion]
    async fn generate_full_order(&self, storage: &S, hash: &Hash, base: &Hash, base_height: u64, base_topo_height: u64) -> Result<Vec<Hash>, BlockchainError> {
        let block_tips = {
            let mut cache = self.full_order_cache.lock().await;
            // check if its present in the cache first
            if let Some(value) = cache.get(&(hash.clone(), base.clone(), base_height)) {
                trace!("Found full order in cache: {}", value.iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "));
                return Ok(value.clone())
            }

            let block_tips = storage.get_past_blocks_for_block_hash(hash).await?;
            // only the genesis block can have 0 tips, returns its hash
            if block_tips.len() == 0 {
                let result = vec![GENESIS_BLOCK_HASH.clone()];
                cache.put((hash.clone(), base.clone(), base_height), result.clone());
                return Ok(result)
            }

            // if the block has been previously ordered, return it as base
            if hash == base {
                let result = vec![base.clone()];
                cache.put((hash.clone(), base.clone(), base_height), result.clone());
                return Ok(result)
            }

            block_tips
        };

        let mut scores = Vec::new();
        for hash in block_tips.iter() {
            let is_ordered = storage.is_block_topological_ordered(hash).await;
            if !is_ordered || (is_ordered && storage.get_topo_height_for_hash(hash).await? >= base_topo_height) {
                let diff = storage.get_cumulative_difficulty_for_block_hash(hash).await?;
                scores.push((hash, diff));
            } else {
                debug!("Block {} is skipped in generate_full_order, is ordered = {}, base topo height = {}", hash, is_ordered, base_topo_height);
            }
        }

        blockdag::sort_descending_by_cumulative_difficulty(&mut scores);

        // let's build the right order now
        let mut order: Vec<Hash> = Vec::new();
        for (hash, _) in scores {
            let sub_order = self.generate_full_order(storage, hash, base, base_height, base_topo_height).await?;
            for order_hash in sub_order {
                if !order.contains(&order_hash) {
                    order.push(order_hash);
                }
            }
        }

        order.push(hash.clone());

        // save in cache final result
        let mut cache = self.full_order_cache.lock().await;
        cache.put((hash.clone(), base.clone(), base_height), order.clone());

        Ok(order)
    }

    // confirms whether the actual tip difficulty is withing 9% deviation with best tip (reference)
    async fn validate_tips(&self, storage: &S, best_tip: &Hash, tip: &Hash) -> Result<bool, BlockchainError> {
        let best_difficulty = storage.get_difficulty_for_block_hash(best_tip).await?;
        let block_difficulty = storage.get_difficulty_for_block_hash(tip).await?;

        Ok(best_difficulty * 91 / 100 < block_difficulty)
    }

    // TODO generic tips type
    pub async fn get_difficulty_at_tips<D: DifficultyProvider>(&self, provider: &D, tips: &Vec<Hash>) -> Result<Difficulty, BlockchainError> {
        if tips.len() == 0 { // Genesis difficulty
            return Ok(GENESIS_BLOCK_DIFFICULTY)
        }

        let height = blockdag::calculate_height_at_tips(provider, tips).await?;
        if height < 3 {
            return Ok(MINIMUM_DIFFICULTY)
        }

        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(provider, tips).await?;
        let biggest_difficulty = provider.get_difficulty_for_block_hash(best_tip).await?;
        let best_tip_timestamp = provider.get_timestamp_for_block_hash(best_tip).await?;

        let parent_tips = provider.get_past_blocks_for_block_hash(best_tip).await?;
        let parent_best_tip = blockdag::find_best_tip_by_cumulative_difficulty(provider, &parent_tips).await?;
        let parent_best_tip_timestamp = provider.get_timestamp_for_block_hash(parent_best_tip).await?;
 
        let difficulty = calculate_difficulty(parent_best_tip_timestamp, best_tip_timestamp, biggest_difficulty);
        Ok(difficulty)
    }

    pub fn get_difficulty(&self) -> Difficulty {
        self.difficulty.load(Ordering::SeqCst)
    }

    // pass in params the already computed block hash and its tips
    // check the difficulty calculated at tips
    // if the difficulty is valid, returns it (prevent to re-compute it)
    pub async fn verify_proof_of_work<D: DifficultyProvider>(&self, provider: &D, hash: &Hash, tips: &Vec<Hash>) -> Result<u64, BlockchainError> {
        let difficulty = self.get_difficulty_at_tips(provider, tips).await?;
        if self.simulator || check_difficulty(hash, difficulty)? {
            Ok(difficulty)
        } else {
            Err(BlockchainError::InvalidDifficulty)
        }
    }

    pub fn get_p2p(&self) -> &RwLock<Option<Arc<P2pServer<S>>>> {
        &self.p2p
    }

    pub fn get_rpc(&self) -> &RwLock<Option<SharedDaemonRpcServer<S>>> {
        &self.rpc
    }

    pub fn get_storage(&self) -> &RwLock<S> {
        &self.storage
    }

    pub fn get_mempool(&self) -> &RwLock<Mempool> {
        &self.mempool
    }

    pub async fn add_tx_to_mempool(&self, tx: Transaction, broadcast: bool) -> Result<(), BlockchainError> {
        let hash = tx.hash();
        self.add_tx_to_mempool_with_hash(tx, hash, broadcast).await
    }


    pub async fn add_tx_to_mempool_with_hash<'a>(&'a self, tx: Transaction, hash: Hash, broadcast: bool) -> Result<(), BlockchainError> {
        let tx = Arc::new(tx);
        {
            let storage = self.storage.read().await;
            let mut mempool = self.mempool.write().await;
    
            if mempool.contains_tx(&hash) {
                return Err(BlockchainError::TxAlreadyInMempool(hash))
            }
    
            // check that the TX is not already in blockchain
            if storage.is_tx_executed_in_a_block(&hash)? {
                return Err(BlockchainError::TxAlreadyInBlockchain(hash))
            }
    
            // get the highest nonce for this owner
            let owner = tx.get_owner();
            // get the highest nonce available
            // if presents, it means we have at least one tx from this owner in mempool
            if let Some(cache) = mempool.get_cached_nonce(owner) {
                // we accept to delete a tx from mempool if the new one has a higher fee
                if let Some(hash) = cache.has_tx_with_same_nonce(tx.get_nonce()) {
                    // TX is in range, we have to delete an existing TX
                    // check that fees are higher than the future deleted one
                    let other_tx = mempool.view_tx(hash)?;
                    if other_tx.get_fee() >= tx.get_fee() {
                        return Err(BlockchainError::InvalidTxFee(other_tx.get_fee() + 1, tx.get_fee()));
                    }
                }

                // check that the nonce is in the range
                if !(tx.get_nonce() <= cache.get_max() + 1 && tx.get_nonce() >= cache.get_min()) {
                    debug!("TX {} nonce is not in the range of the pending TXs for this owner, received: {}, expected between {} and {}", hash, tx.get_nonce(), cache.get_min(), cache.get_max());
                    return Err(BlockchainError::InvalidTxNonceMempoolCache)
                }
                // we need to do it in two times because of the constraint of lifetime on &tx
                let mut balances = HashMap::new();
                let mut nonces = HashMap::new();
                // because we already verified the range of nonce
                nonces.insert(tx.get_owner(), tx.get_nonce());

                // Verify original TX
                // We may have double spending in balances, but it is ok because miner check that all txs included are valid
                self.verify_transaction_with_hash(&storage, &tx, &hash, &mut balances, Some(&mut nonces), false).await?;
            } else {
                let mut balances = HashMap::new();
                self.verify_transaction_with_hash(&storage, &tx, &hash, &mut balances, None, false).await?;
            }

            mempool.add_tx(hash.clone(), tx.clone())?;
        }

        if broadcast {
            // P2p broadcast to others peers
            if let Some(p2p) = self.p2p.read().await.as_ref() {
                p2p.broadcast_tx_hash(hash.clone()).await;
            }

            // broadcast to websocket this tx
            if let Some(rpc) = self.rpc.read().await.as_ref() {
                // Notify miners if getwork is enabled
                if let Some(getwork) = rpc.getwork_server() {
                    if let Err(e) = getwork.notify_new_job_rate_limited().await {
                        debug!("Error while notifying miners for new tx: {}", e);
                    }
                }

                if rpc.is_event_tracked(&NotifyEvent::TransactionAddedInMempool).await {
                    let data: TransactionResponse<'_, Arc<Transaction>> = TransactionResponse {
                        blocks: None,
                        executed_in_block: None,
                        in_mempool: true,
                        first_seen: Some(get_current_time()),
                        data: DataHash { hash: Cow::Owned(hash), data: Cow::Borrowed(&tx) }
                    };

                    if let Err(e) = rpc.notify_clients(&NotifyEvent::TransactionAddedInMempool, json!(data)).await {
                        debug!("Error while broadcasting event TransactionAddedInMempool to websocket: {}", e);
                    }
                }
            }
        }
        
        Ok(())
    }

    // this will be used in future for hard fork versions
    pub fn get_version_at_height(&self, _height: u64) -> u8 {
        0
    }

    pub async fn get_block_template(&self, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_block_template_for_storage(&storage, address).await
    }

    // check that the TX Hash is present in mempool or in chain disk
    pub async fn has_tx(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        // check in mempool first
        // if its present, returns it
        {
            let mempool = self.mempool.read().await;
            if mempool.contains_tx(hash) {
                return Ok(true)
            }
        }

        // check in storage now
        let storage = self.storage.read().await;
        storage.has_transaction(hash).await
    }

    // retrieve the TX based on its hash by searching in mempool then on disk
    pub async fn get_tx(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        trace!("get tx {} from blockchain", hash);
        // check in mempool first
        // if its present, returns it
        {
            trace!("Locking mempool for get tx {}", hash);
            let mempool = self.mempool.read().await;
            trace!("Mempool locked for get tx {}", hash);
            if let Ok(tx) = mempool.get_tx(hash) {
                return Ok(tx)
            } 
        }

        // check in storage now
        let storage = self.storage.read().await;
        storage.get_transaction(hash).await
    }

    pub async fn get_block_template_for_storage(&self, storage: &S, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        let extra_nonce: [u8; EXTRA_NONCE_SIZE] = rand::thread_rng().gen::<[u8; EXTRA_NONCE_SIZE]>(); // generate random bytes
        let tips_set = storage.get_tips().await?;
        let mut tips = Vec::with_capacity(tips_set.len());
        for hash in tips_set {
            tips.push(hash);
        }

        if tips.len() > 1 {
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, &tips).await?.clone();
            debug!("Best tip selected for this block template is {}", best_tip);
            let mut selected_tips = Vec::with_capacity(tips.len());
            for hash in tips {
                if best_tip != hash {
                    if !self.validate_tips(storage, &best_tip, &hash).await? {
                        debug!("Tip {} is invalid, not selecting it because difficulty can't be less than 91% of {}", hash, best_tip);
                        continue;
                    }
                }
                selected_tips.push(hash);
            }
            tips = selected_tips;
        }

        let mut sorted_tips = blockdag::sort_tips(storage, &tips).await.unwrap();
        if sorted_tips.len() > TIPS_LIMIT {
            let dropped_tips = sorted_tips.drain(TIPS_LIMIT..); // keep only first 3 heavier tips
            for hash in dropped_tips {
                debug!("Dropping tip {} because it is not in the first 3 heavier tips", hash);
            }
        }

        let height = blockdag::calculate_height_at_tips(storage, &sorted_tips).await?;
        let mut block = BlockHeader::new(self.get_version_at_height(height), height, get_current_timestamp(), sorted_tips, extra_nonce, address, Vec::new());

        trace!("Locking mempool for building block template");
        let mempool = self.mempool.read().await;
        trace!("Mempool locked for building block template");

        // get all availables txs and sort them by fee per size
        let mut txs = mempool.get_txs()
            .iter()
            .map(|(hash, tx)| (tx.get_fee(), tx.get_size(), hash, tx.get_tx()))
            .collect::<Vec<_>>();
        txs.sort_by(|(a_fee, a_size, _, a_tx), (b_fee, b_size, _, b_tx)| {
            // If its the same sender, check the nonce
            if a_tx.get_owner() == b_tx.get_owner() {
                // Increasing nonces (lower first)
                let cmp = a_tx.get_nonce().cmp(&b_tx.get_nonce());
                // If its not equal nonce, returns it
                if cmp != std::cmp::Ordering::Equal {
                    return cmp
                }
            }

            let a = a_fee * *a_size as u64;
            let b = b_fee * *b_size as u64;
            // Decreasing fees (higher first)
            b.cmp(&a)
        });

        let mut total_txs_size = 0;
        let mut nonces: HashMap<&PublicKey, u64> = HashMap::new();
        let mut block_size = block.size();
        {
            let mut balances = HashMap::new();
            'main: for (fee, size, hash, tx) in txs {
                if block_size + total_txs_size + size >= MAX_BLOCK_SIZE {
                    break 'main;
                }

                // Check if the TX is valid for this potential block
                trace!("Checking TX {} with nonce {}", hash, tx.get_nonce());
                if let Err(e) = self.verify_transaction_with_hash(&storage, tx, hash, &mut balances, Some(&mut nonces), false).await {
                    warn!("TX {} is not valid for mining: {}", hash, e);
                } else {
                    trace!("Selected {} (nonce: {}, fees: {}) for mining", hash, tx.get_nonce(), format_xelis(fee));
                    // TODO no clone
                    block.txs_hashes.push(hash.as_ref().clone());
                    block_size += HASH_SIZE; // add the hash size
                    total_txs_size += size;
                }
            }
        }
        Ok(block)
    }

    pub async fn build_block_from_header(&self, header: Immutable<BlockHeader>) -> Result<Block, BlockchainError> {
        trace!("Searching TXs for block at height {}", header.get_height());
        let mut transactions: Vec<Immutable<Transaction>> = Vec::with_capacity(header.get_txs_count());
        let storage = self.storage.read().await;
        trace!("Locking mempool for building block from header");
        let mempool = self.mempool.read().await;
        trace!("Mempool lock acquired for building block from header");
        for hash in header.get_txs_hashes() {
            trace!("Searching TX {} for building block", hash);
            // at this point, we don't want to lose/remove any tx, we clone it only
            let tx = if mempool.contains_tx(hash) {
                mempool.get_tx(hash)?
            } else {
                storage.get_transaction(hash).await?
            };

            transactions.push(Immutable::Arc(tx));
        }
        let block = Block::new(header, transactions);
        Ok(block)
    }

    pub async fn add_new_block(&self, block: Block, broadcast: bool, mining: bool) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.add_new_block_for_storage(&mut storage, block, broadcast, mining).await
    }

    pub async fn add_new_block_for_storage(&self, storage: &mut S, block: Block, broadcast: bool, mining: bool) -> Result<(), BlockchainError> {
        let start = Instant::now();
        let block_hash = block.hash();
        debug!("Add new block {}", block_hash);
        if storage.has_block(&block_hash).await? {
            error!("Block {} is already in chain!", block_hash);
            return Err(BlockchainError::AlreadyInChain)
        }

        if block.get_timestamp() > get_current_timestamp() + TIMESTAMP_IN_FUTURE_LIMIT { // accept 2s in future
            error!("Block timestamp is too much in future!");
            return Err(BlockchainError::TimestampIsInFuture(get_current_timestamp(), block.get_timestamp()));
        }

        let tips_count = block.get_tips().len();
        debug!("Tips count for this new {}: {}", block, tips_count);
        if tips_count > TIPS_LIMIT {
            error!("Invalid tips count, got {} but maximum allowed is {}", tips_count, TIPS_LIMIT);
            return Err(BlockchainError::InvalidTips) // only 3 tips are allowed
        }

        let current_height = self.get_height();
        if tips_count == 0 && current_height != 0 {
            error!("Expected at least one previous block for this block {}", block_hash);
            return Err(BlockchainError::ExpectedTips)
        }

        // block contains header and full TXs
        if block.size() > MAX_BLOCK_SIZE {
            error!("Block size ({} bytes) is greater than the limit ({} bytes)", block.size(), MAX_BLOCK_SIZE);
            return Err(BlockchainError::InvalidBlockSize(MAX_BLOCK_SIZE, block.size()));
        }

        {
            let mut cache = HashSet::with_capacity(tips_count);
            for tip in block.get_tips() {
                if !storage.has_block(tip).await? {
                    error!("This block ({}) has a TIP ({}) which is not present in chain", block_hash, tip);
                    return Err(BlockchainError::InvalidTips)
                }

                if cache.contains(tip) {
                    error!("This block ({}) has a TIP ({}) which is duplicated", block_hash, tip);
                    return Err(BlockchainError::InvalidTips)
                }
                cache.insert(tip);
            }
        }

        let block_height_by_tips = blockdag::calculate_height_at_tips(storage, block.get_tips()).await?;
        if block_height_by_tips != block.get_height() {
            error!("Invalid block height {}, expected {} for this block {}", block.get_height(), block_height_by_tips, block_hash);
            return Err(BlockchainError::InvalidBlockHeight(block_height_by_tips, block.get_height()))
        }

        let stable_height = self.get_stable_height();
        if tips_count > 0 {
            debug!("Height by tips: {}, stable height: {}", block_height_by_tips, stable_height);

            if block_height_by_tips < stable_height {
                error!("Invalid block height by tips {} for this block ({}), its height is in stable height {}", block_height_by_tips, block_hash, stable_height);
                return Err(BlockchainError::InvalidBlockHeightStableHeight)
            }
        }

        if !self.verify_non_reachability(storage, &block).await? {
            error!("{} with hash {} has an invalid reachability", block, block_hash);
            return Err(BlockchainError::InvalidReachability)
        }

        for hash in block.get_tips() {
            let previous_timestamp = storage.get_timestamp_for_block_hash(hash).await?;
            if previous_timestamp > block.get_timestamp() { // block timestamp can't be less than previous block.
                error!("Invalid block timestamp, parent ({}) is less than new block {}", hash, block_hash);
                return Err(BlockchainError::TimestampIsLessThanParent(block.get_timestamp()));
            }

            trace!("calculate distance from mainchain for tips: {}", hash);
            let distance = self.calculate_distance_from_mainchain(storage, hash).await?;
            if distance <= current_height && current_height - distance >= STABLE_LIMIT {
                error!("{} with hash {} have deviated too much, maximum allowed is {} (current height: {}, distance: {})", block, block_hash, STABLE_LIMIT, current_height, distance);
                return Err(BlockchainError::BlockDeviation)
            }
        }

        if tips_count > 1 {
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, block.get_tips()).await?;
            debug!("Best tip selected for this new block is {}", best_tip);
            for hash in block.get_tips() {
                if best_tip != hash {
                    if !self.validate_tips(storage, best_tip, hash).await? {
                        error!("Tip {} is invalid, difficulty can't be less than 91% of {}", hash, best_tip);
                        return Err(BlockchainError::InvalidTips)
                    }
                }
            }
        }

        // verify PoW and get difficulty for this block based on tips
        let pow_hash = block.get_pow_hash();
        debug!("POW hash: {}", pow_hash);
        let difficulty = self.verify_proof_of_work(storage, &pow_hash, block.get_tips()).await?;
        debug!("PoW is valid for difficulty {}", difficulty);

        { // Transaction verification
            let hashes_len = block.get_txs_hashes().len();
            let txs_len = block.get_transactions().len();
            if  hashes_len != txs_len {
                error!("Block {} has an invalid block header, transaction count mismatch (expected {} got {})!", block_hash, txs_len, hashes_len);
                return Err(BlockchainError::InvalidBlockTxs(hashes_len, txs_len));
            }

            let mut cache_account: HashMap<&PublicKey, u64> = HashMap::new();
            let mut cache_tx: HashMap<Hash, bool> = HashMap::new(); // avoid using a TX multiple times
            let mut balances = HashMap::new();
            let mut all_parents_txs: Option<HashSet<Hash>> = None;
            for (tx, hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) {
                // verification that the real TX Hash is the same as in block header (and also check the correct order)
                let tx_hash = tx.hash();
                if tx_hash != *hash {
                    error!("Invalid tx {} vs {} in block header", tx_hash, hash);
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                }

                debug!("Verifying TX {}", tx_hash);

                // block can't contains the same tx and should have tx hash in block header
                if cache_tx.contains_key(&tx_hash) {
                    error!("Block cannot contains the same TX {}", tx_hash);
                    return Err(BlockchainError::TxAlreadyInBlock(tx_hash));
                }

                // check that the TX included is not executed in stable height or in block TIPS
                if storage.is_tx_executed_in_a_block(hash)? {
                    let block_executed = storage.get_block_executer_for_tx(hash)?;
                    debug!("Tx {} was executed in {}", hash, block);
                    let block_height = storage.get_height_for_block_hash(&block_executed).await?;
                    // if the tx was executed below stable height, reject whole block!
                    if block_height <= stable_height {
                        error!("Block {} contains a dead tx {}", block_hash, tx_hash);
                        return Err(BlockchainError::DeadTx(tx_hash))
                    } else {
                        debug!("Tx {} was executed in block {} at height {} (unstable height: {})", tx_hash, block, block_height, stable_height);
                        // now we should check that the TX was not executed in our TIP branch
                        // because that mean the miner was aware of the TX execution and still include it
                        if all_parents_txs.is_none() {
                            // load it only one time
                            all_parents_txs = Some(self.get_all_txs_until_height(storage, stable_height, block.get_tips()).await?);
                        }

                        // if its the case, we should reject the block
                        if let Some(txs) = all_parents_txs.as_ref() {
                            // miner knows this tx was already executed because its present in block tips
                            // reject the whole block
                            if txs.contains(&tx_hash) {
                                error!("Malicious Block {} formed, contains a dead tx {}", block_hash, tx_hash);
                                return Err(BlockchainError::DeadTx(tx_hash))
                            } else {
                                // otherwise, all looks good but because the TX was executed in another branch, we skip verification
                                // DAG will choose which branch will execute the TX
                                info!("TX {} was executed in another branch, skipping verification", tx_hash);
                                // increase the total size
                                // add tx hash in cache
                                cache_tx.insert(tx_hash, true);
                                // because TX was already validated & executed and is not in block tips
                                // we can safely skip the verification of this TX
                                continue;
                            }
                        } else {
                            // impossible to happens because we compute it if value is None
                            error!("FATAL ERROR! Unable to load all TXs until height {}", stable_height);
                            return Err(BlockchainError::Unknown)
                        }
                    }
                }

                self.verify_transaction_with_hash(storage, tx, &tx_hash, &mut balances, Some(&mut cache_account), false).await?;

                // add tx hash in cache
                cache_tx.insert(tx_hash, true);
            }

            if cache_tx.len() != txs_len || cache_tx.len() != hashes_len {
                error!("Invalid count in TXs, received only {} unique txs", cache_tx.len());
                return Err(BlockchainError::InvalidBlockTxs(block.get_txs_hashes().len(), cache_tx.len()))
            }
        }

        // Save transactions & block
        let (block, txs) = block.split();
        let block = block.to_arc();
        debug!("Saving block {} on disk", block_hash);
        // Add block to chain
        storage.add_new_block(block.clone(), &txs, difficulty, block_hash.clone()).await?;

        // Compute cumulative difficulty for block
        let cumulative_difficulty = {
            let cumulative_difficulty: Difficulty = if tips_count == 0 {
                GENESIS_BLOCK_DIFFICULTY
            } else {
                let (base, base_height) = self.find_common_base(storage, block.get_tips()).await?;
                let (_, cumulative_difficulty) = self.find_tip_work_score(&storage, &block_hash, &base, base_height).await?;
                cumulative_difficulty
            };
            storage.set_cumulative_difficulty_for_block_hash(&block_hash, cumulative_difficulty).await?;
            debug!("Cumulative difficulty for block {}: {}", block_hash, cumulative_difficulty);
            cumulative_difficulty
        };

        debug!("Locking mempool write mode");
        let mut mempool = self.mempool.write().await;
        debug!("mempool write mode ok");

        let mut tips = storage.get_tips().await?;
        tips.insert(block_hash.clone());
        for hash in block.get_tips() {
            tips.remove(hash);
        }
        debug!("New tips: {}", tips.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","));

        let (base_hash, base_height) = self.find_common_base(storage, &tips).await?;
        let best_tip = self.find_best_tip(storage, &tips, &base_hash, base_height).await?;
        debug!("Best tip selected: {}", best_tip);

        let base_topo_height = storage.get_topo_height_for_hash(&base_hash).await?;
        // generate a full order until base_topo_height
        let mut full_order = self.generate_full_order(storage, &best_tip, &base_hash, base_height, base_topo_height).await?;
        debug!("Generated full order size: {}, with base ({}) topo height: {}", full_order.len(), base_hash, base_topo_height);

        // rpc server lock
        let rpc_server = self.rpc.read().await;
        let should_track_events = if let Some(rpc) = rpc_server.as_ref() {
            rpc.get_tracked_events().await
        } else {
            HashSet::new()
        };
        
        // track all changes in nonces to clean mempool from invalid txs stuck
        let mut nonces: HashMap<PublicKey, u64> = HashMap::new();
        // track all events to notify websocket
        let mut events: HashMap<NotifyEvent, Vec<Value>> = HashMap::new();

        let mut current_topoheight = self.get_topo_height();
        // order the DAG (up to TOP_HEIGHT - STABLE_LIMIT)
        let mut highest_topo = 0;
        {
            let mut is_written = base_topo_height == 0;
            let mut skipped = 0;
            // detect which part of DAG reorg stay, for other part, undo all executed txs
            debug!("Detecting stable point of DAG and cleaning txs above it");
            {
                let mut topoheight = base_topo_height;
                while topoheight <= current_topoheight {
                    let hash_at_topo = storage.get_hash_at_topo_height(topoheight).await?;
                    trace!("Cleaning txs at topoheight {} ({})", topoheight, hash_at_topo);
                    if !is_written {
                        if let Some(order) = full_order.get(0) {
                            // Verify that the block is still at the same topoheight
                            if storage.is_block_topological_ordered(order).await && *order == hash_at_topo {
                                trace!("Hash {} at topo {} stay the same, skipping cleaning", hash_at_topo, topoheight);
                                // remove the hash from the order because we don't need to recompute it
                                full_order.remove(0);
                                topoheight += 1;
                                skipped += 1;
                                continue;
                            }
                        }
                        // if we are here, it means that the block was re-ordered
                        is_written = true;
                    }

                    trace!("Cleaning transactions executions at topo height {} (block {})", topoheight, hash_at_topo);

                    let block = storage.get_block_header_by_hash(&hash_at_topo).await?;

                    // mark txs as unexecuted if it was executed in this block
                    for tx_hash in block.get_txs_hashes() {
                        if storage.is_tx_executed_in_block(tx_hash, &hash_at_topo)? {
                            trace!("Removing execution of {}", tx_hash);
                            storage.remove_tx_executed(&tx_hash)?;
                        }
                    }

                    topoheight += 1;
                }
            }

            // time to order the DAG that is moving
            debug!("Ordering blocks based on generated DAG order ({} blocks)", full_order.len());
            for (i, hash) in full_order.into_iter().enumerate() {
                highest_topo = base_topo_height + skipped + i as u64;

                // if block is not re-ordered and it's not genesis block
                // because we don't need to recompute everything as it's still good in chain
                if !is_written && tips_count != 0 && storage.is_block_topological_ordered(&hash).await && storage.get_topo_height_for_hash(&hash).await? == highest_topo {
                    trace!("Block ordered {} stay at topoheight {}. Skipping...", hash, highest_topo);
                    continue;
                }
                is_written = true;

                trace!("Ordering block {} at topoheight {}", hash, highest_topo);

                storage.set_topo_height_for_block(&hash, highest_topo).await?;
                let past_supply = if highest_topo == 0 {
                    0
                } else {
                    storage.get_supply_at_topo_height(highest_topo - 1).await?
                };

                let block_reward = if self.is_side_block(storage, &hash).await? {
                    trace!("Block {} at topoheight {} is a side block", hash, highest_topo);
                    let reward = get_block_reward(past_supply);
                    reward * SIDE_BLOCK_REWARD_PERCENT / 100
                } else {
                    get_block_reward(past_supply)
                };

                trace!("set block reward to {} at {}", block_reward, highest_topo);
                storage.set_block_reward_at_topo_height(highest_topo, block_reward)?;
                
                let supply = past_supply + block_reward;
                trace!("set block supply to {} at {}", supply, highest_topo);
                storage.set_supply_at_topo_height(highest_topo, supply)?;

                // track all changes in balances
                let mut balances: HashMap<&PublicKey, HashMap<&Hash, VersionedBalance>> = HashMap::new();
                let block = storage.get_block(&hash).await?;
                let mut total_fees = 0;

                // compute rewards & execute txs
                let mut local_nonces = HashMap::new();
                for (tx, tx_hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) { // execute all txs
                    // TODO improve it (too much read/write that can be refactored)
                    if !storage.has_block_linked_to_tx(&tx_hash, &hash)? {
                        storage.add_block_for_tx(&tx_hash, &hash)?;
                        trace!("Block {} is now linked to tx {}", hash, tx_hash);
                    }

                    // check that the tx was not yet executed in another tip branch
                    if storage.is_tx_executed_in_a_block(tx_hash)? {
                        trace!("Tx {} was already executed in a previous block, skipping...", tx_hash);
                    } else {
                        // tx was not executed, but lets check that it is not a potential double spending
                        // check that the nonce is not lower than the one already executed
                        // nonce here is tx nonce of previous execution + 1
                        if let Some(nonce) = nonces.get(tx.get_owner()) {
                            if tx.get_nonce() < *nonce {
                                warn!("Tx {} is a potential double spending, skipping...", tx_hash);
                                // TX will be orphaned
                                continue;
                            }
                        }
                        // mark tx as executed
                        trace!("Executing tx {} in block {}", tx_hash, hash);
                        storage.set_tx_executed_in_block(tx_hash, &hash)?;

                        self.execute_transaction(storage, &tx, &mut local_nonces, &mut balances, highest_topo).await?;    
                        // if the rpc_server is enable, track events
                        if should_track_events.contains(&NotifyEvent::TransactionExecuted) {
                            let value = json!(TransactionExecutedEvent {
                                tx_hash: Cow::Borrowed(&tx_hash),
                                block_hash: Cow::Borrowed(&hash),
                                topoheight: highest_topo,
                            });
                            events.entry(NotifyEvent::TransactionExecuted).or_insert_with(Vec::new).push(value);
                        }
                        total_fees += tx.get_fee();
                    }
                }

                // reward the miner
                self.reward_miner(storage, &block, block_reward, total_fees, &mut balances, highest_topo).await?;

                // save balances for each topoheight
                for (key, assets) in balances {
                    for (asset, balance) in assets {
                        trace!("Saving balance {} for {} at topo {}, previous: {:?}", asset, key, highest_topo, balance.get_previous_topoheight());
                        // Save the balance as the latest one
                        storage.set_balance_to(key, asset, highest_topo, &balance).await?;
                    }

                    // No nonce update for this key
                    if !local_nonces.contains_key(key) {
                        // Check if its a known account, otherwise set nonce to 0
                        if !storage.has_nonce(key).await? {
                            // This public key is new, register it by setting 0
                            storage.set_nonce_at_topoheight(key, 0, highest_topo).await?;
                        }
                    }
                }

                // save nonces for each pubkey for new topoheight
                for (key, nonce) in local_nonces {
                    trace!("Saving nonce {} for {} at topoheight {}", nonce, key, highest_topo);
                    storage.set_nonce_at_topoheight(&key, nonce, highest_topo).await?;

                    // insert in "global" nonces map for easier mempool cleaning
                    nonces.insert(key, nonce);
                }

                if should_track_events.contains(&NotifyEvent::BlockOrdered) {
                    let value = json!(BlockOrderedEvent {
                        block_hash: Cow::Borrowed(&hash),
                        block_type: get_block_type_for_block(self, &storage, &hash).await.unwrap_or(BlockType::Normal),
                        topoheight: highest_topo,
                    });
                    events.entry(NotifyEvent::BlockOrdered).or_insert_with(Vec::new).push(value);
                }
            }

        }

        let best_height = storage.get_height_for_block_hash(best_tip).await?;
        let mut new_tips = Vec::new();
        for hash in tips {
            let tip_base_distance = self.calculate_distance_from_mainchain(storage, &hash).await?;
            trace!("tip base distance: {}, best height: {}", tip_base_distance, best_height);
            if tip_base_distance <= best_height && best_height - tip_base_distance < STABLE_LIMIT - 1 {
                trace!("Adding {} as new tips", hash);
                new_tips.push(hash);
            } else {
                warn!("Rusty TIP declared stale {} with best height: {}, tip base distance: {}", hash, best_height, tip_base_distance);
            }
        }

        tips = HashSet::new();
        debug!("find best tip by cumulative difficulty");
        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, &new_tips).await?.clone();
        for hash in new_tips {
            if best_tip != hash {
                if !self.validate_tips(&storage, &best_tip, &hash).await? {
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
        let extended = highest_topo > current_topoheight;
        if current_height == 0 || extended {
            debug!("Blockchain height extended, current topoheight is now {} (previous was {})", highest_topo, current_topoheight);
            storage.set_top_topoheight(highest_topo)?;
            self.topoheight.store(highest_topo, Ordering::Release);
            current_topoheight = highest_topo;
        }

        // auto prune mode
        if extended {
            if let Some(keep_only) = self.auto_prune_keep_n_blocks {
                // check that the topoheight is greater than the safety limit
                // and that we can prune the chain using the config while respecting the safety limit
                if current_topoheight % keep_only == 0 {
                    info!("Auto pruning chain until topoheight {} (keep only {} blocks)", current_topoheight - keep_only, keep_only);
                    if let Err(e) = self.prune_until_topoheight_for_storage(current_topoheight - keep_only, storage).await {
                        warn!("Error while trying to auto prune chain: {}", e);
                    }
                }
            }
        }

        storage.store_tips(&tips)?;

        let mut current_height = current_height;
        if current_height == 0 || block.get_height() > current_height {
            debug!("storing new top height {}", block.get_height());
            storage.set_top_height(block.get_height())?;
            self.height.store(block.get_height(), Ordering::Release);
            current_height = block.get_height();
        }
        if storage.is_block_topological_ordered(&block_hash).await {
            let topoheight = storage.get_topo_height_for_hash(&block_hash).await?;
            debug!("Adding new '{}' {} at topoheight {}", block_hash, block, topoheight);
        } else {
            // this means the block is considered as orphaned yet
            debug!("Adding new '{}' {} with no topoheight (not ordered)!", block_hash, block);
        }

        // update stable height and difficulty in cache
        {
            let (_, height) = self.find_common_base(&storage, &tips).await?;
            if should_track_events.contains(&NotifyEvent::StableHeightChanged) { // detect the change in stable height
                let previous_stable_height = self.get_stable_height();
                if height != previous_stable_height {
                    let value = json!(StableHeightChangedEvent {
                        previous_stable_height,
                        new_stable_height: height
                    });
                    events.entry(NotifyEvent::StableHeightChanged).or_insert_with(Vec::new).push(value);
                }
            }
            self.stable_height.store(height, Ordering::SeqCst);

            trace!("update difficulty in cache");
            let mut tips_vec = Vec::with_capacity(tips.len());
            for hash in tips {
                tips_vec.push(hash);
            }
            let difficulty = self.get_difficulty_at_tips(storage, &tips_vec).await?;
            self.difficulty.store(difficulty, Ordering::SeqCst);
        }

        // Clean all old txs
        mempool.clean_up(nonces).await;

        debug!("Processed block {} in {}ms", block_hash, start.elapsed().as_millis());

        if broadcast {
            trace!("Broadcasting block");
            if let Some(p2p) = self.p2p.read().await.as_ref() {
                trace!("P2p locked, broadcasting in new task");
                let p2p = p2p.clone();
                let pruned_topoheight = storage.get_pruned_topoheight()?;
                let block_hash = block_hash.clone();
                tokio::spawn(async move {
                    debug!("broadcast block to peers");
                    p2p.broadcast_block(&block, cumulative_difficulty, current_topoheight, current_height, pruned_topoheight, &block_hash, mining).await;
                });
            }
        }

        // broadcast to websocket new block
        if let Some(rpc) = rpc_server.as_ref() {
            // if we have a getwork server, notify miners
            if let Some(getwork) = rpc.getwork_server() {
                let getwork = getwork.clone();
                tokio::spawn(async move {
                    if let Err(e) = getwork.notify_new_job().await {
                        debug!("Error while notifying new job to miners: {}", e);
                    }
                });
            }

            // notify websocket clients
            trace!("Notifying websocket clients");
            if should_track_events.contains(&NotifyEvent::NewBlock) {
                match get_block_response_for_hash(self, storage, block_hash, false).await {
                    Ok(response) => {
                        events.entry(NotifyEvent::NewBlock).or_insert_with(Vec::new).push(response);
                    },
                    Err(e) => {
                        debug!("Error while getting block response for websocket: {}", e);
                    }
                };
            }

            let rpc = rpc.clone();
            // don't block mutex/lock more than necessary, we move it in another task
            tokio::spawn(async move {
                for (event, values) in events {
                    for value in values {
                        if let Err(e) = rpc.notify_clients(&event, value).await {
                            debug!("Error while broadcasting event to websocket: {}", e);
                        }
                    }
                }
            });
        }

        Ok(())
    }

    // retrieve all txs hashes until height or until genesis block
    // for this we get all tips and recursively retrieve all txs from tips until we reach height
    async fn get_all_txs_until_height(&self, storage: &S, until_height: u64, tips: &Vec<Hash>) -> Result<HashSet<Hash>, BlockchainError> {
        let mut hashes = HashSet::new();
        let mut blocks_processed: HashSet<Hash> = HashSet::new();
        let mut queue: Vec<Hash> = Vec::new();
        queue.extend_from_slice(tips);

        while !queue.is_empty() {
            // get last element from queue (order doesn't matter and its faster than moving all elements)
            let hash = queue.remove(queue.len() - 1);
            let block = storage.get_block_header_by_hash(&hash).await?;

            // add it in cache to not re-process it again
            blocks_processed.insert(hash);

            // check that the block height is higher than the height passed in param
            if until_height < block.get_height() {
                // add all txs from block
                for tx in block.get_txs_hashes() {
                    hashes.insert(tx.clone());
                }

                // add all tips from block (but check that we didn't already added it)
                for tip in block.get_tips() {
                    if !blocks_processed.contains(tip) {
                        queue.push(tip.clone());
                    }
                }
            }
        }

        Ok(hashes)
    }

    // if a block is not ordered, it's an orphaned block and its transactions are not honoured
    pub async fn is_block_orphaned_for_storage(&self, storage: &S, hash: &Hash) -> bool {
        trace!("is block {} orphaned", hash);
        !storage.is_block_topological_ordered(hash).await
    }

    // a block is a side block if its ordered and its block height is less than or equal to height of past 8 topographical blocks
    pub async fn is_side_block(&self, storage: &S, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("is block {} a side block", hash);
        if !storage.is_block_topological_ordered(hash).await {
            return Ok(false)
        }

        let topoheight = storage.get_topo_height_for_hash(hash).await?;
        // genesis block can't be a side block
        if topoheight == 0 {
            return Ok(false)
        }

        let height = storage.get_height_for_block_hash(hash).await?;

        // verify if there is a block with height higher than this block in past 8 topo blocks
        let mut counter = 0;
        let mut i = topoheight - 1;
        while counter < STABLE_LIMIT && i > 0 {
            let hash = storage.get_hash_at_topo_height(i).await?;
            let previous_height = storage.get_height_for_block_hash(&hash).await?;

            if height <= previous_height {
                return Ok(true)
            }
            counter += 1;
            i -= 1;
        }

        Ok(false)
    }

    // to have stable order: it must be ordered, and be under the stable height limit
    pub async fn has_block_stable_order(&self, storage: &S, hash: &Hash, topoheight: u64) -> Result<bool, BlockchainError> {
        trace!("has block {} stable order at topoheight {}", hash, topoheight);
        if storage.is_block_topological_ordered(hash).await {
            let block_topo_height = storage.get_topo_height_for_hash(hash).await?;
            return Ok(block_topo_height + STABLE_LIMIT <= topoheight)
        }
        Ok(false)
    }

    pub async fn rewind_chain(&self, count: u64) -> Result<u64, BlockchainError> {
        let mut storage = self.storage.write().await;
        self.rewind_chain_for_storage(&mut storage, count).await
    }

    pub async fn rewind_chain_for_storage(&self, storage: &mut S, count: u64) -> Result<u64, BlockchainError> {
        trace!("rewind chain with count = {}", count);
        let current_height = self.get_height();
        let current_topoheight = self.get_topo_height();
        warn!("Rewind chain with count = {}, height = {}, topoheight = {}", count, current_height, current_topoheight);
        let (new_height, new_topoheight, txs) = storage.pop_blocks(current_height, current_topoheight, count).await?;
        debug!("New topoheight: {} (diff: {})", new_topoheight, current_topoheight - new_topoheight);

        {
            for (hash, tx) in txs {
                debug!("Trying to add TX {} to mempool again", hash);
                if let Err(e) = self.add_tx_to_mempool_with_hash(tx.as_ref().clone(), hash, false).await {
                    debug!("TX rewinded is not compatible anymore: {}", e);
                }
            }
        }

        self.height.store(new_height, Ordering::Release);
        self.topoheight.store(new_topoheight, Ordering::Release);
        // update stable height
        {
            let tips = storage.get_tips().await?;
            let (_, height) = self.find_common_base(&storage, &tips).await?;

            // if we have a RPC server, propagate the StableHeightChanged if necessary
            if let Some(rpc) = self.rpc.read().await.as_ref() {
                let previous_stable_height = self.get_stable_height();
                if height != previous_stable_height {
                    if rpc.is_event_tracked(&NotifyEvent::StableHeightChanged).await {
                        let rpc = rpc.clone();
                        tokio::spawn(async move {
                            let event = json!(StableHeightChangedEvent {
                                previous_stable_height,
                                new_stable_height: height
                            });
    
                            if let Err(e) = rpc.notify_clients(&NotifyEvent::StableHeightChanged, event).await {
                                debug!("Error while broadcasting event StableHeightChanged to websocket: {}", e);
                            }
                        });
                    }
                }
            }
            self.stable_height.store(height, Ordering::Release);
        }

        Ok(new_topoheight)
    }

    // verify the transaction and returns fees available
    // nonces allow us to support multiples tx from same owner in the same block
    // txs must be sorted in ascending order based on account nonce
    async fn verify_transaction_with_hash<'a>(&self, storage: &S, tx: &'a Transaction, hash: &Hash, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, u64>>, nonces: Option<&mut HashMap<&'a PublicKey, u64>>, skip_nonces: bool) -> Result<(), BlockchainError> {
        trace!("Verify transaction with hash {}", hash);

        if !tx.verify_signature() {
            return Err(BlockchainError::InvalidTransactionSignature)
        }

        let owner_balances: &mut HashMap<&'a Hash, u64> = balances.entry(tx.get_owner()).or_insert_with(HashMap::new);
        {
            let balance = match owner_balances.entry(&XELIS_ASSET) {
                Entry::Vacant(entry) => {
                    let (_, balance) = storage.get_last_balance(tx.get_owner(), &XELIS_ASSET).await?;
                    entry.insert(balance.get_balance())
                },
                Entry::Occupied(entry) => entry.into_mut(),
            };

            if let Some(value) = balance.checked_sub(tx.get_fee()) {
                *balance = value;
            } else {
                warn!("Overflow detected using fees ({} XEL) in transaction {}", format_xelis(tx.get_fee()), hash);
                return Err(BlockchainError::Overflow)
            }
        }

        match tx.get_data() {
            TransactionType::Transfer(txs) => {
                if txs.len() == 0 { // don't accept any empty tx
                    return Err(BlockchainError::TxEmpty(hash.clone()))
                }

                // invalid serde tx
                if txs.len() > u8::MAX as usize {
                    return Err(BlockchainError::TooManyOutputInTx(hash.clone()))
                }

                let mut extra_data_size = 0; 
                for output in txs {
                    if output.to == *tx.get_owner() { // we can't transfer coins to ourself, why would you do that ?
                        return Err(BlockchainError::InvalidTransactionToSender(hash.clone()))
                    }

                    if let Some(data) = &output.extra_data {
                        extra_data_size += data.len();
                    }

                    let balance = match owner_balances.entry(&output.asset) {
                        Entry::Vacant(entry) => {
                            let (_, balance) = storage.get_last_balance(tx.get_owner(), &XELIS_ASSET).await?;
                            entry.insert(balance.get_balance())
                        },
                        Entry::Occupied(entry) => entry.into_mut(),
                    };
                    if let Some(value) = balance.checked_sub(output.amount) {
                        *balance = value;
                    } else {
                        warn!("Overflow detected with transaction transfer {}", hash);
                        return Err(BlockchainError::Overflow)
                    }
                }

                if extra_data_size > EXTRA_DATA_LIMIT_SIZE {
                    return Err(BlockchainError::InvalidTransactionExtraDataTooBig(EXTRA_DATA_LIMIT_SIZE, extra_data_size))   
                }
            }
            TransactionType::Burn { asset, amount } => {
                if *amount == 0 {
                    error!("Burn Tx {} has no value to burn", hash);
                    return Err(BlockchainError::NoValueForBurn)
                }

                let balance = match owner_balances.entry(asset) {
                    Entry::Vacant(entry) => {
                        let (_, balance) = storage.get_last_balance(tx.get_owner(), asset).await?;
                        entry.insert(balance.get_balance())
                    },
                    Entry::Occupied(entry) => entry.into_mut(),
                };
                if let Some(value) = balance.checked_sub(*amount) {
                    *balance = value;
                } else {
                    warn!("Overflow detected with transaction burn {}", hash);
                    return Err(BlockchainError::Overflow)
                }
            },
            _ => {
                // TODO implement SC
                return Err(BlockchainError::SmartContractTodo)
            }
        };

        if !skip_nonces {
            // nonces can be already pre-computed to support multi nonces at the same time in block/mempool
            if let Some(nonces) = nonces {
                // check that we don't have nonce from cache and that it exists in storage, otherwise set 0
                let nonce = match nonces.entry(tx.get_owner()) {
                    Entry::Vacant(entry) => {
                        let nonce = if storage.has_nonce(tx.get_owner()).await? {
                            let (_, version) = storage.get_last_nonce(tx.get_owner()).await?;
                            version.get_nonce()
                        } else {
                            0
                        };
                        entry.insert(nonce)
                    },
                    Entry::Occupied(entry) => entry.into_mut(),
                };
    
                if *nonce != tx.get_nonce() {
                    debug!("Invalid nonce from cache for tx {}", hash);
                    return Err(BlockchainError::InvalidTxNonce(hash.clone(), tx.get_nonce(), *nonce, tx.get_owner().clone()))
                }
                // we increment it in case any new tx for same owner is following
                *nonce += 1;
            } else { // We don't have any cache, compute using chain data
                // it is possible that a miner has balance but no nonces, so we need to check it
                let nonce = if storage.has_nonce(tx.get_owner()).await? {
                    let (_, version) = storage.get_last_nonce(tx.get_owner()).await?;
                    version.get_nonce()
                } else {
                    0 // no nonce, so we start at 0
                };

                if nonce != tx.get_nonce() {
                    debug!("Invalid nonce in storage for tx {}", hash);
                    return Err(BlockchainError::InvalidTxNonce(hash.clone(), tx.get_nonce(), nonce, tx.get_owner().clone()))
                }
            }
        }

        Ok(())
    }

    // retrieve the already added balance with changes OR generate a new versioned balance
    async fn retrieve_balance<'a, 'b>(&self, storage: &S, balances: &'b mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, key: &'a PublicKey, asset: &'a Hash, topoheight: u64) -> Result<&'b mut VersionedBalance, BlockchainError> {
        trace!("retrieve balance {} for {} at topoheight {}", asset, key, topoheight);
        let assets = balances.entry(key).or_insert_with(HashMap::new);
        Ok(match assets.entry(asset) {
            Entry::Occupied(v) => v.into_mut(),
            Entry::Vacant(v) => {
                let balance = storage.get_new_versioned_balance(key, asset, topoheight).await?;
                v.insert(balance)
            }
        })
    }

    // this function just add to balance
    // its used to centralize all computation
    async fn add_balance<'a>(&self, storage: &S, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, key: &'a PublicKey, asset: &'a Hash, amount: u64, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("add balance {} for {} at topoheight {} with {}", asset, key, topoheight, amount);
        let version = self.retrieve_balance(storage, balances, key, asset, topoheight).await?;
        version.add_balance(amount);
        Ok(())
    }

    // this function just subtract from balance
    // its used to centralize all computation
    async fn sub_balance<'a>(&self, storage: &S, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, key: &'a PublicKey, asset: &'a Hash, amount: u64, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("sub balance {} for {} at topoheight {} with {}", asset, key, topoheight, amount);
        let version = self.retrieve_balance(storage, balances, key, asset, topoheight).await?;
        version.sub_balance(amount);
        Ok(())
    }

    // reward block miner and dev fees if any.
    async fn reward_miner<'a>(&self, storage: &S, block: &'a BlockHeader, mut block_reward: u64, total_fees: u64, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, topoheight: u64) -> Result<(), BlockchainError> {
        debug!("reward miner {} at topoheight {} with block reward = {}, total fees = {}", block.get_miner(), topoheight, block_reward, total_fees);
        // if dev fee are enabled, give % from block reward only
        if DEV_FEE_PERCENT != 0 {
            let dev_fee = block_reward * DEV_FEE_PERCENT / 100;
            debug!("adding {}% to dev address for dev fees", DEV_FEE_PERCENT);
            block_reward -= dev_fee;
            self.add_balance(storage, balances, &DEV_PUBLIC_KEY, &XELIS_ASSET, dev_fee, topoheight).await?;
        }

        // now we reward the miner with block reward and total fees
        self.add_balance(storage, balances, block.get_miner(), &XELIS_ASSET, block_reward + total_fees, topoheight).await
    }

    async fn execute_transaction<'a>(&self, storage: &mut S, transaction: &'a Transaction, nonces: &mut HashMap<PublicKey, u64>, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, topoheight: u64) -> Result<(), BlockchainError> {
        let mut total_deducted: HashMap<&'a Hash, u64> = HashMap::new();
        total_deducted.insert(&XELIS_ASSET, transaction.get_fee());

        match transaction.get_data() {
            TransactionType::Burn { asset, amount } => {
                *total_deducted.entry(asset).or_insert(0) += amount;
            }
            TransactionType::Transfer(txs) => {
                for output in txs {
                    // update receiver's account
                    self.add_balance(storage, balances, &output.to, &output.asset, output.amount, topoheight).await?;
                    *total_deducted.entry(&output.asset).or_insert(0) += output.amount;
                }
            }
            _ => {
                return Err(BlockchainError::SmartContractTodo)
            }
        };

        // now we substract all assets spent from this sender
        for (asset, amount) in total_deducted {
            self.sub_balance(storage, balances, transaction.get_owner(), asset, amount, topoheight).await?;
        }

        // no need to read from disk, transaction nonce has been verified already
        let nonce = transaction.get_nonce() + 1;
        if let Some(stored_nonce) = nonces.get_mut(transaction.get_owner()) {
            // only put the new nonce if it's higher than the current one
            // in case of "lost race" side blocks (block which are higher in topoheight and less in height)
            if *stored_nonce < nonce {
                *stored_nonce = nonce;
            }
        } else {
            nonces.insert(transaction.get_owner().clone(), nonce);
        }

        Ok(())
    }

    pub async fn get_average_block_time_for_storage(&self, storage: &S) -> Result<u64, BlockchainError> {
        // current topoheight
        let topoheight = self.get_topo_height();

        // we need to get the block hash at topoheight - 50 to compare
        // if topoheight is 0, returns the target as we don't have any block
        // otherwise returns topoheight
        let mut count = if topoheight > 50 {
            50
        } else if topoheight == 0 {
            return Ok(BLOCK_TIME_MILLIS);
        } else {
            topoheight
        };

        // check that we are not under the pruned topoheight
        if let Some(pruned_topoheight) = storage.get_pruned_topoheight()? {
            if topoheight - count < pruned_topoheight {
                count = pruned_topoheight
            }
        }

        let now_hash = storage.get_hash_at_topo_height(topoheight).await?;
        let now_timestamp = storage.get_timestamp_for_block_hash(&now_hash).await?;

        let count_hash = storage.get_hash_at_topo_height(topoheight - count).await?;
        let count_timestamp = storage.get_timestamp_for_block_hash(&count_hash).await?;

        let diff = (now_timestamp - count_timestamp) as u64;
        Ok(diff / count)
    }
}

pub fn get_block_reward(supply: u64) -> u64 {
    // Prevent any overflow
    if supply >= MAX_SUPPLY {
        // Max supply reached, do we want to generate small fixed amount of coins? 
        return 0
    }

    let base_reward = (MAX_SUPPLY - supply) >> EMISSION_SPEED_FACTOR;
    base_reward * BLOCK_TIME / 180
}