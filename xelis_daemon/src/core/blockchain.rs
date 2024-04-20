use anyhow::Error;
use indexmap::IndexSet;
use lru::LruCache;
use serde_json::{Value, json};
use xelis_common::{
    api::{
        daemon::{
            BlockOrderedEvent,
            BlockOrphanedEvent,
            BlockType,
            NotifyEvent,
            StableHeightChangedEvent,
            TransactionExecutedEvent,
            TransactionResponse
        },
        RPCTransaction
    },
    asset::AssetData,
    block::{
        Block,
        BlockHeader,
        EXTRA_NONCE_SIZE
    },
    config::{
        COIN_DECIMALS,
        MAXIMUM_SUPPLY,
        MAX_TRANSACTION_SIZE,
        TIPS_LIMIT,
        XELIS_ASSET
    },
    crypto::{
        Hash,
        Hashable,
        PublicKey,
        HASH_SIZE
    },
    difficulty::{check_difficulty, CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    network::Network,
    serializer::Serializer,
    time::{
        get_current_time_in_millis,
        get_current_time_in_seconds,
        TimestampMillis
    },
    transaction::{verify::BlockchainVerificationState, Transaction, TransactionType},
    utils::{calculate_tx_fee, format_xelis},
    varuint::VarUint
};
use crate::{
    config::{
        get_genesis_block_hash, get_hex_genesis_block, get_minimum_difficulty,
        BLOCK_TIME_MILLIS, CHAIN_SYNC_RESPONSE_MAX_BLOCKS, CHAIN_SYNC_RESPONSE_MIN_BLOCKS,
        DEFAULT_CACHE_SIZE, DEFAULT_P2P_BIND_ADDRESS, DEFAULT_RPC_BIND_ADDRESS, DEV_FEES,
        DEV_PUBLIC_KEY, EMISSION_SPEED_FACTOR, GENESIS_BLOCK_DIFFICULTY, MAX_BLOCK_SIZE,
        MILLIS_PER_SECOND, P2P_DEFAULT_MAX_PEERS, SIDE_BLOCK_REWARD_MAX_BLOCKS, PRUNE_SAFETY_LIMIT,
        SIDE_BLOCK_REWARD_PERCENT, SIDE_BLOCK_REWARD_MIN_PERCENT, STABLE_LIMIT, TIMESTAMP_IN_FUTURE_LIMIT
    },
    core::{
        blockdag,
        difficulty,
        error::BlockchainError,
        mempool::Mempool,
        nonce_checker::NonceChecker,
        simulator::Simulator,
        storage::{DagOrderProvider, DifficultyProvider, Storage},
        tx_selector::{TxSelector, TxSelectorEntry},
        state::{ChainState, ApplicableChainState},
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
        HashMap,
        hash_map::Entry,
        HashSet,
        VecDeque
    },
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc
    },
    time::Instant
};
use tokio::sync::{Mutex, RwLock};
use log::{info, error, debug, warn, trace};
use rand::Rng;

use super::storage::{
    BlocksAtHeightProvider,
    ClientProtocolProvider,
    PrunedTopoheightProvider,
    AccountProvider
};

#[derive(Debug, clap::Args)]
pub struct Config {
    /// Optional node tag
    #[clap(long)]
    pub tag: Option<String>,
    /// P2p bind address to listen for incoming connections
    #[clap(long, default_value_t = String::from(DEFAULT_P2P_BIND_ADDRESS))]
    pub p2p_bind_address: String,
    /// Number of maximums peers allowed
    #[clap(long, default_value_t = P2P_DEFAULT_MAX_PEERS)]
    pub max_peers: usize,
    /// Rpc bind address to listen for HTTP requests
    #[clap(long, default_value_t = String::from(DEFAULT_RPC_BIND_ADDRESS))]
    pub rpc_bind_address: String,
    /// Add a priority node to connect when P2p is started.
    /// A priority node is connected only one time.
    #[clap(long)]
    pub priority_nodes: Vec<String>,
    /// An exclusive node is connected and its connection is maintained in case of disconnect
    /// it also replaces seed nodes.
    #[clap(long)]
    pub exclusive_nodes: Vec<String>,
    /// Set dir path for blockchain storage.
    /// This will be appended by the network name for the database directory.
    /// It must ends with a slash.
    #[clap(long)]
    pub dir_path: Option<String>,
    /// Set LRUCache size (0 = disabled).
    #[clap(long, default_value_t = DEFAULT_CACHE_SIZE)]
    pub cache_size: usize,
    /// Disable GetWork Server (WebSocket for miners).
    #[clap(long)]
    pub disable_getwork_server: bool,
    /// Enable the simulator (skip PoW verification, generate a new block for every BLOCK_TIME).
    #[clap(long)]
    pub simulator: Option<Simulator>,
    /// Disable the p2p connections.
    #[clap(long)]
    pub disable_p2p_server: bool,
    /// Enable the auto prune mode and prune the chain
    /// at each new block by keeping at least N blocks
    /// before the top.
    #[clap(long)]
    pub auto_prune_keep_n_blocks: Option<u64>,
    /// Allow fast sync mode.
    /// 
    /// Sync a bootstrapped chain if your local copy is outdated.
    /// 
    /// It will not store any blocks / TXs and will not verify the history locally.
    /// 
    /// Use it with extreme cautions and trusted nodes to have a valid bootstrapped chain.
    #[clap(long)]
    pub allow_fast_sync: bool,
    /// Allow boost chain sync mode.
    /// 
    /// This will request in parallel all blocks instead of sequentially.
    /// 
    /// It is not enabled by default because it will requests several blocks before validating each previous.
    #[clap(long)]
    pub allow_boost_sync: bool,
    /// Configure the maximum chain response size.
    /// 
    /// This is useful for low devices who want to reduce resources usage
    /// and for high-end devices who want to (or help others to) sync faster.
    #[clap(long)]
    pub max_chain_response_size: Option<usize>,
    /// Ask peers to not share our IP to others and/or through API.
    /// 
    /// This is useful for people that don't want that their IP is revealed in RPC API
    /// and/or shared to others nodes as a potential new peer to connect to.
    /// 
    /// Note that it may prevent to have new incoming peers.
    #[clap(long, default_value = "false")]
    pub disable_ip_sharing: bool
}

pub struct Blockchain<S: Storage> {
    // current block height
    height: AtomicU64,
    // current topo height
    topoheight: AtomicU64,
    // current stable height
    stable_height: AtomicU64,
    // Determine which last block is stable
    // It is used mostly for chain rewind limit
    stable_topoheight: AtomicU64,
    // mempool to retrieve/add all txs
    mempool: RwLock<Mempool>,
    // storage to retrieve/add blocks
    storage: RwLock<S>,
    // P2p module
    p2p: RwLock<Option<Arc<P2pServer<S>>>>,
    // RPC module
    rpc: RwLock<Option<SharedDaemonRpcServer<S>>>,
    // current difficulty at tips
    // its used as cache to display current network hashrate
    difficulty: Mutex<Difficulty>,
    // used to skip PoW verification
    simulator: Option<Simulator>,
    // current network type on which one we're using/connected to
    network: Network,
    // this cache is used to avoid to recompute the common base for each block and is mandatory
    // key is (tip hash, tip height) while value is (base hash, base height)
    tip_base_cache: Mutex<LruCache<(Hash, u64), (Hash, u64)>>,
    // tip work score is used to determine the best tip based on a block, tip base ands a base height
    tip_work_score_cache: Mutex<LruCache<(Hash, Hash, u64), (HashSet<Hash>, CumulativeDifficulty)>>,
    // using base hash, current tip hash and base height, this cache is used to store the DAG order
    full_order_cache: Mutex<LruCache<(Hash, Hash, u64), IndexSet<Hash>>>,
    // auto prune mode if enabled, will delete all blocks every N and keep only N top blocks (topoheight based)
    auto_prune_keep_n_blocks: Option<u64>
}

impl<S: Storage> Blockchain<S> {
    pub async fn new(config: Config, network: Network, storage: S) -> Result<Arc<Self>, Error> {
        // Do some checks on config params
        {
            if config.simulator.is_some() && network != Network::Dev {
                error!("Impossible to enable simulator mode except in dev network!");
                return Err(BlockchainError::InvalidNetwork.into())
            }
    
            if let Some(keep_only) = config.auto_prune_keep_n_blocks {
                if keep_only < PRUNE_SAFETY_LIMIT {
                    error!("Auto prune mode should keep at least 80 blocks");
                    return Err(BlockchainError::AutoPruneMode.into())
                }
            }

            if let Some(size) = config.max_chain_response_size {
                if size < CHAIN_SYNC_RESPONSE_MIN_BLOCKS || size > CHAIN_SYNC_RESPONSE_MAX_BLOCKS {
                    error!("Max chain response size should be in inclusive range of [{}-{}]", CHAIN_SYNC_RESPONSE_MIN_BLOCKS, CHAIN_SYNC_RESPONSE_MAX_BLOCKS);
                    return Err(BlockchainError::ConfigMaxChainResponseSize.into())
                }
            }

            if config.allow_boost_sync && config.allow_fast_sync {
                error!("Boost sync and fast sync can't be enabled at the same time!");
                return Err(BlockchainError::ConfigSyncMode.into())
            }
        }

        let on_disk = storage.has_blocks().await;
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
            stable_topoheight: AtomicU64::new(0),
            mempool: RwLock::new(Mempool::new(network)),
            storage: RwLock::new(storage),
            p2p: RwLock::new(None),
            rpc: RwLock::new(None),
            difficulty: Mutex::new(GENESIS_BLOCK_DIFFICULTY),
            simulator: config.simulator,
            network,
            tip_base_cache: Mutex::new(LruCache::new(NonZeroUsize::new(1024).unwrap())),
            tip_work_score_cache: Mutex::new(LruCache::new(NonZeroUsize::new(1024).unwrap())),
            full_order_cache: Mutex::new(LruCache::new(NonZeroUsize::new(1024).unwrap())),
            auto_prune_keep_n_blocks: config.auto_prune_keep_n_blocks
        };

        // include genesis block
        if !on_disk {
            blockchain.create_genesis_block().await?;
        } else {
            debug!("Retrieving tips for computing current difficulty");
            let storage = blockchain.get_storage().read().await;
            let tips_set = storage.get_tips().await?;
            let (difficulty, _) = blockchain.get_difficulty_at_tips(&*storage, tips_set.iter()).await?;
            blockchain.set_difficulty(difficulty).await;
        }

        // now compute the stable height
        {
            debug!("Retrieving tips for computing current stable height");
            let storage = blockchain.get_storage().read().await;
            let tips = storage.get_tips().await?;
            let (stable_hash, stable_height) = blockchain.find_common_base::<S, _>(&storage, &tips).await?;
            blockchain.stable_height.store(stable_height, Ordering::SeqCst);
            // Search the stable topoheight
            let stable_topoheight = storage.get_topo_height_for_hash(&stable_hash).await?;
            blockchain.stable_topoheight.store(stable_topoheight, Ordering::SeqCst);
        }

        let arc = Arc::new(blockchain);
        // create P2P Server
        if !config.disable_p2p_server {
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

            match P2pServer::new(config.dir_path, config.tag, config.max_peers, config.p2p_bind_address, Arc::clone(&arc), exclusive_nodes.is_empty(), exclusive_nodes, config.allow_fast_sync, config.allow_boost_sync, config.max_chain_response_size, !config.disable_ip_sharing) {
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
            info!("RPC Server will listen on: {}", config.rpc_bind_address);
            match DaemonRpcServer::new(config.rpc_bind_address, Arc::clone(&arc), config.disable_getwork_server).await {
                Ok(server) => *arc.rpc.write().await = Some(server),
                Err(e) => error!("Error while starting RPC server: {}", e)
            };
        }

        // Start the simulator task if necessary
        if let Some(simulator) = arc.simulator {
            warn!("Simulator {} mode enabled!", simulator);
            let blockchain = Arc::clone(&arc);
            tokio::spawn(async move {
                simulator.start(blockchain).await;
            });
        }

        Ok(arc)
    }

    // Detect if the simulator task has been started
    pub fn is_simulator_enabled(&self) -> bool {
        self.simulator.is_some()
    }

    // Stop all blockchain modules
    // Each module is stopped in its own context
    // So no deadlock occurs in case they are linked
    pub async fn stop(&self) {
        info!("Stopping modules...");
        {
            let mut p2p = self.p2p.write().await;
            if let Some(p2p) = p2p.take() {
                p2p.stop().await;
            }
        }

        {
            let mut rpc = self.rpc.write().await;
            if let Some(rpc) = rpc.take() {
                rpc.stop().await;
            }
        }

        {
            let mut storage = self.storage.write().await;
            if let Err(e) = storage.stop().await {
                error!("Error while stopping storage: {}", e);
            }
        }

        info!("All modules are now stopped!");
    }

    // Reload the storage and update all cache values
    // Clear the mempool also in case of not being up-to-date
    pub async fn reload_from_disk(&self) -> Result<(), BlockchainError> {
        trace!("Reloading chain from disk");
        let storage = self.storage.read().await;
        let topoheight = storage.get_top_topoheight()?;
        let height = storage.get_top_height()?;
        self.topoheight.store(topoheight, Ordering::SeqCst);
        self.height.store(height, Ordering::SeqCst);

        let tips = storage.get_tips().await?;
        // Research stable height to update caches
        let (stable_hash, stable_height) = self.find_common_base(&*storage, &tips).await?;
        self.stable_height.store(stable_height, Ordering::SeqCst);

        // Research stable topoheight also
        let stable_topoheight = storage.get_topo_height_for_hash(&stable_hash).await?;
        self.stable_topoheight.store(stable_topoheight, Ordering::SeqCst);

        // Recompute the difficulty with new tips
        let (difficulty, _) = self.get_difficulty_at_tips(&*storage, tips.iter()).await?;
        self.set_difficulty(difficulty).await;

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

        let (genesis_block, genesis_hash) = if let Some(genesis_block) = get_hex_genesis_block(&self.network) {
            info!("De-serializing genesis block for network {}...", self.network);
            let genesis = Block::from_hex(genesis_block.to_owned())?;
            if *genesis.get_miner() != *DEV_PUBLIC_KEY {
                return Err(BlockchainError::GenesisBlockMiner)
            }

            let expected_hash = genesis.hash();
            let genesis_hash = get_genesis_block_hash(&self.network);
            if *genesis_hash != expected_hash {
                error!("Genesis block hash is invalid! Expected: {}, got: {}", expected_hash, genesis_hash);
                return Err(BlockchainError::InvalidGenesisHash)
            }

            (genesis, expected_hash)
        } else {
            warn!("No genesis block found!");
            info!("Generating a new genesis block...");
            let header = BlockHeader::new(0, 0, get_current_time_in_millis(), IndexSet::new(), [0u8; EXTRA_NONCE_SIZE], DEV_PUBLIC_KEY.clone(), IndexSet::new());
            let block = Block::new(Immutable::Owned(header), Vec::new());
            let block_hash = block.hash();
            info!("Genesis generated: {} with {:?} {}", block.to_hex(), block_hash, block_hash);
            (block, block_hash)
        };

        debug!("Adding genesis block '{}' to chain", genesis_hash);

        // hardcode genesis block topoheight
        storage.set_topo_height_for_block(&genesis_block.hash(), 0).await?;
        storage.set_top_height(0)?;

        self.add_new_block_for_storage(&mut storage, genesis_block, false, false).await?;

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
        let mut hash = header.get_pow_hash()?;
        let mut current_height = self.get_height();
        while !self.is_simulator_enabled() && !check_difficulty(&hash, &difficulty)? {
            if self.get_height() != current_height {
                current_height = self.get_height();
                header = self.get_block_template(key.clone()).await?;
            }
            header.nonce += 1;
            header.timestamp = get_current_time_in_millis();
            hash = header.get_pow_hash()?;
        }

        let block = self.build_block_from_header(Immutable::Owned(header)).await?;
        let block_height = block.get_height();
        info!("Mined a new block {} at height {}", hash, block_height);
        Ok(block)
    }

    // Prune the chain until topoheight
    // This will delete all blocks / versioned balances / txs until topoheight in param
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

        // 1 is to not delete the genesis block
        let last_pruned_topoheight = storage.get_pruned_topoheight().await?.unwrap_or(1);
        if topoheight < last_pruned_topoheight {
            return Err(BlockchainError::PruneLowerThanLastPruned)
        }

        // find new stable point based on a sync block under the limit topoheight
        let located_sync_topoheight = self.locate_nearest_sync_block_for_topoheight::<S>(&storage, topoheight, self.get_height()).await?;
        debug!("Located sync topoheight found: {}", located_sync_topoheight);
        
        if located_sync_topoheight > last_pruned_topoheight {
            // create snapshots of balances to located_sync_topoheight
            storage.create_snapshot_balances_at_topoheight(located_sync_topoheight).await?;
            storage.create_snapshot_nonces_at_topoheight(located_sync_topoheight).await?;
            storage.create_snapshot_registrations_at_topoheight(located_sync_topoheight).await?;

            // delete all blocks until the new topoheight
            for topoheight in last_pruned_topoheight..located_sync_topoheight {
                trace!("Pruning block at topoheight {}", topoheight);
                // delete block
                let _ = storage.delete_block_at_topoheight(topoheight).await?;
            }

            // delete balances for all assets
            storage.delete_versioned_balances_below_topoheight(located_sync_topoheight).await?;
            // delete nonces versions
            storage.delete_versioned_nonces_below_topoheight(located_sync_topoheight).await?;
            // Also delete registrations
            storage.delete_registrations_below_topoheight(located_sync_topoheight).await?;

            // Update the pruned topoheight
            storage.set_pruned_topoheight(located_sync_topoheight).await?;
            Ok(located_sync_topoheight)
        } else {
            debug!("located_sync_topoheight <= topoheight, no pruning needed");
            Ok(last_pruned_topoheight)
        }
    }

    // determine the topoheight of the nearest sync block until limit topoheight
    pub async fn locate_nearest_sync_block_for_topoheight<P>(&self, provider: &P, mut topoheight: u64, current_height: u64) -> Result<u64, BlockchainError>
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
    pub fn get_height(&self) -> u64 {
        self.height.load(Ordering::Acquire)
    }

    // returns the highest topological height
    pub fn get_topo_height(&self) -> u64 {
        self.topoheight.load(Ordering::Acquire)
    }

    // Get the current block height stable
    // No blocks can be added at or below this height
    pub fn get_stable_height(&self) -> u64 {
        self.stable_height.load(Ordering::Acquire)
    }

    // Get the stable topoheight
    // It is used to determine at which DAG topological height
    // the block is in case of rewind
    pub fn get_stable_topoheight(&self) -> u64 {
        self.stable_topoheight.load(Ordering::Acquire)
    }

    // Get the network on which this chain is running
    pub fn get_network(&self) -> &Network {
        &self.network
    }

    // Get the current emitted supply of XELIS at current topoheight
    pub async fn get_supply(&self) -> Result<u64, BlockchainError> {
        self.storage.read().await.get_supply_at_topo_height(self.get_topo_height()).await
    }

    // Get the count of transactions available in the mempool
    pub async fn get_mempool_size(&self) -> usize {
        self.mempool.read().await.size()
    }

    // Get the current top block hash in chain
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

    // Verify if we have the current block in storage by locking it ourself
    pub async fn has_block(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        let storage = self.storage.read().await;
        storage.has_block_with_hash(hash).await
    }

    // Verify if the block is a sync block for current chain height
    pub async fn is_sync_block(&self, storage: &S, hash: &Hash) -> Result<bool, BlockchainError> {
        let current_height = self.get_height();
        self.is_sync_block_at_height::<S>(storage, hash, current_height).await
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
            return Ok(true)
        }

        // block must be ordered and in stable height
        if block_height + STABLE_LIMIT > height || !provider.is_block_topological_ordered(hash).await {
            return Ok(false)
        }

        // We are only pruning at sync block
        if let Some(pruned_topo) = provider.get_pruned_topoheight().await? {
            let topoheight = provider.get_topo_height_for_hash(hash).await?;
            if pruned_topo == topoheight {
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
        let mut blocks_in_main_chain = 0;
        for hash in tips_at_height {
            if provider.is_block_topological_ordered(&hash).await {
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
            let blocks = provider.get_blocks_at_height(i).await?;
            pre_blocks.extend(blocks);
            i -= 1;
        }

        let sync_block_cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(hash).await?;
        // if potential sync block has lower cumulative difficulty than one of past blocks, it is not a sync block
        for pre_hash in pre_blocks {
            // We compare only against block ordered otherwise we can have desync between node which could lead to fork
            // This is rare event but can happen
            if provider.is_block_topological_ordered(&pre_hash).await {
                let cumulative_difficulty = provider.get_cumulative_difficulty_for_block_hash(&pre_hash).await?;
                if cumulative_difficulty >= sync_block_cumulative_difficulty {
                    warn!("Block {} at height {} is not a sync block, it has lower cumulative difficulty than block {} at height {}", hash, block_height, pre_hash, i);
                    return Ok(false)
                }
            }
        }

        Ok(true)
    }

    async fn find_tip_base<P>(&self, provider: &P, hash: &Hash, height: u64, pruned_topoheight: u64) -> Result<(Hash, u64), BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider
    {
        let mut cache = self.tip_base_cache.lock().await;

        let mut stack: VecDeque<Hash> = VecDeque::new();
        stack.push_back(hash.clone());

        let mut bases: IndexSet<(Hash, u64)> = IndexSet::new();

        'main: while let Some(current_hash) = stack.pop_back() {
            trace!("Finding tip base for {} at height {}", current_hash, height);
            if pruned_topoheight > 0 && provider.is_block_topological_ordered(&current_hash).await {
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
                if pruned_topoheight > 0 && provider.is_block_topological_ordered(&tip_hash).await {
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

                // Tip was not sync, we need to find its tip base too
                stack.push_back(tip_hash.clone());
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
        P: DifficultyProvider + DagOrderProvider + BlocksAtHeightProvider + PrunedTopoheightProvider,
        I: IntoIterator<Item = &'a Hash> + Copy,
    {
        debug!("Searching for common base for tips {}", tips.into_iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "));
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
        Ok((base_hash, base_height))
    }

    async fn build_reachability(&self, storage: &S, hash: Hash) -> Result<HashSet<Hash>, BlockchainError> {
        let mut set = HashSet::new();
        let mut stack: VecDeque<(Hash, u64)> = VecDeque::new();
        stack.push_back((hash, 0));
    
        while let Some((current_hash, current_level)) = stack.pop_back() {
            if current_level >= 2 * STABLE_LIMIT {
                trace!("Level limit reached, adding {}", current_hash);
                set.insert(current_hash);
            } else {
                trace!("Level {} reached with hash {}", current_level, current_hash);
                let tips = storage.get_past_blocks_for_block_hash(&current_hash).await?;
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
    async fn verify_non_reachability(&self, storage: &S, tips: &IndexSet<Hash>) -> Result<bool, BlockchainError> {
        trace!("Verifying non reachability for block");
        let tips_count = tips.len();
        let mut reach = Vec::with_capacity(tips_count);
        for hash in tips {
            let set = self.build_reachability(storage, hash.clone()).await?;
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
    async fn find_lowest_height_from_mainchain<P>(&self, provider: &P, hash: Hash) -> Result<u64, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        // Lowest height found from mainchain
        let mut lowest_height = u64::max_value();
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
                if provider.is_block_topological_ordered(tip_hash).await {
                    let height = provider.get_height_for_block_hash(tip_hash).await?;
                    if lowest_height > height {
                        lowest_height = height;
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
    async fn calculate_distance_from_mainchain<P>(&self, provider: &P, hash: &Hash) -> Result<u64, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        if provider.is_block_topological_ordered(hash).await {
            let height = provider.get_height_for_block_hash(hash).await?;
            debug!("calculate_distance: Block {} is at height {}", hash, height);
            return Ok(height)
        }
        debug!("calculate_distance: Block {} is not ordered, calculate distance from mainchain", hash);
        let lowest_height = self.find_lowest_height_from_mainchain(provider, hash.clone()).await?;

        debug!("calculate_distance: lowest height found is {}", lowest_height);
        Ok(lowest_height)
    }

    // Find tip work score internal for a block hash
    // this will recursively find all tips and their difficulty
    async fn find_tip_work_score_internal<'a, P>(&self, provider: &P, map: &mut HashMap<Hash, CumulativeDifficulty>, hash: &'a Hash, base_topoheight: u64) -> Result<(), BlockchainError>
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
                    let is_ordered = provider.is_block_topological_ordered(tip_hash).await;
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
    pub async fn find_tip_work_score<P>(&self, provider: &P, hash: &Hash, base: &Hash, base_height: u64) -> Result<(HashSet<Hash>, CumulativeDifficulty), BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        let mut cache = self.tip_work_score_cache.lock().await;
        if let Some(value) = cache.get(&(hash.clone(), base.clone(), base_height)) {
            trace!("Found tip work score in cache: set [{}], height: {}", value.0.iter().map(|h| h.to_string()).collect::<Vec<String>>().join(", "), value.1);
            return Ok(value.clone())
        }

        let block = provider.get_block_header_by_hash(hash).await?;
        let mut map: HashMap<Hash, CumulativeDifficulty> = HashMap::new();
        let base_topoheight = provider.get_topo_height_for_hash(base).await?;
        for hash in block.get_tips() {
            if !map.contains_key(hash) {
                let is_ordered = provider.is_block_topological_ordered(hash).await;
                if !is_ordered || (is_ordered && provider.get_topo_height_for_hash(hash).await? >= base_topoheight) {
                    self.find_tip_work_score_internal(provider, &mut map, hash, base_topoheight).await?;
                }
            }
        }

        if base != hash {
            map.insert(base.clone(), provider.get_cumulative_difficulty_for_block_hash(base).await?);
        }
        map.insert(hash.clone(), provider.get_difficulty_for_block_hash(hash).await?.into());

        let mut set = HashSet::with_capacity(map.len());
        let mut score = CumulativeDifficulty::zero();
        for (hash, value) in map {
            set.insert(hash);
            score += value;
        }

        // save this result in cache
        cache.put((hash.clone(), base.clone(), base_height), (set.clone(), score));

        Ok((set, score))
    }

    // find the best tip (highest cumulative difficulty)
    // We get their cumulative difficulty and sort them then take the first one
    async fn find_best_tip<'a>(&self, storage: &S, tips: &'a HashSet<Hash>, base: &Hash, base_height: u64) -> Result<&'a Hash, BlockchainError> {
        if tips.len() == 0 {
            return Err(BlockchainError::ExpectedTips)
        }

        let mut scores = Vec::with_capacity(tips.len());
        for hash in tips {
            let (_, cumulative_difficulty) = self.find_tip_work_score::<S>(storage, hash, base, base_height).await?;
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
    async fn generate_full_order<P>(&self, provider: &P, hash: &Hash, base: &Hash, base_height: u64, base_topo_height: u64) -> Result<IndexSet<Hash>, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        trace!("Generating full order for {} with base {}", hash, base);
        let mut cache = self.full_order_cache.lock().await;

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
                let is_ordered = provider.is_block_topological_ordered(tip_hash).await;
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
        if tips.len() == 0 { // Genesis difficulty
            return Ok((GENESIS_BLOCK_DIFFICULTY, difficulty::P))
        }

        let height = blockdag::calculate_height_at_tips(provider, tips.clone().into_iter()).await?;
        // Simulator is enabled, don't calculate difficulty
        if height <= 1 || self.is_simulator_enabled() {
            return Ok((get_minimum_difficulty(self.get_network()), difficulty::P))
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
        let minimum_difficulty = get_minimum_difficulty(self.get_network());
        let (difficulty, p_new) = difficulty::calculate_difficulty(parent_newest_tip_timestamp, newest_tip_timestamp, biggest_difficulty, p, minimum_difficulty);
        Ok((difficulty, p_new))
    }

    // Store the difficulty cache for the latest block
    async fn set_difficulty(&self, difficulty: Difficulty) {
        let mut lock = self.difficulty.lock().await;
        *lock = difficulty;
    }

    // Get the current difficulty target for the next block
    pub async fn get_difficulty(&self) -> Difficulty {
        *self.difficulty.lock().await
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
        if self.is_simulator_enabled() || check_difficulty(hash, &difficulty)? {
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
        self.add_tx_to_mempool_with_hash(tx, hash, broadcast).await
    }

    // Add a tx to the mempool with the given hash, it is not computed and the TX is transformed into an Arc
    pub async fn add_tx_to_mempool_with_hash<'a>(&'a self, tx: Transaction, hash: Hash, broadcast: bool) -> Result<(), BlockchainError> {
        let storage = self.storage.read().await;
        self.add_tx_to_mempool_with_storage_and_hash(&*storage, Arc::new(tx), hash, broadcast).await
    }

    // Add a tx to the mempool with the given hash, it will verify the TX and check that it is not already in mempool or in blockchain
    // and its validity (nonce, balance, etc...)
    pub async fn add_tx_to_mempool_with_storage_and_hash<'a>(&'a self, storage: &S, tx: Arc<Transaction>, hash: Hash, broadcast: bool) -> Result<(), BlockchainError> {
        let tx_size = tx.size();
        if tx_size > MAX_TRANSACTION_SIZE {
            return Err(BlockchainError::TxTooBig(tx_size, MAX_TRANSACTION_SIZE))
        }

        {
            let mut mempool = self.mempool.write().await;
    
            if mempool.contains_tx(&hash) {
                return Err(BlockchainError::TxAlreadyInMempool(hash))
            }
    
            // check that the TX is not already in blockchain
            if storage.is_tx_executed_in_a_block(&hash)? {
                return Err(BlockchainError::TxAlreadyInBlockchain(hash))
            }

            let current_topoheight = self.get_topo_height();
            // get the highest nonce available
            // if presents, it means we have at least one tx from this owner in mempool
            if let Some(cache) = mempool.get_cache_for(tx.get_source()) {
                // we accept to delete a tx from mempool if the new one has a higher fee
                if let Some(hash) = cache.has_tx_with_same_nonce(tx.get_nonce()) {
                    // A TX with the same nonce is already in mempool
                    return Err(BlockchainError::TxNonceAlreadyUsed(tx.get_nonce(), hash.as_ref().clone()))
                }

                // check that the nonce is in the range
                if !(tx.get_nonce() <= cache.get_max() + 1 && tx.get_nonce() >= cache.get_min()) {
                    debug!("TX {} nonce is not in the range of the pending TXs for this owner, received: {}, expected between {} and {}", hash, tx.get_nonce(), cache.get_min(), cache.get_max());
                    return Err(BlockchainError::InvalidTxNonceMempoolCache(tx.get_nonce(), cache.get_min(), cache.get_max()))
                }
            }

            mempool.add_tx(storage, current_topoheight, hash.clone(), tx.clone(), tx_size).await?;
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
                    let data = RPCTransaction::from_tx(&tx, &hash, storage.is_mainnet());
                    let data: TransactionResponse<'_> = TransactionResponse {
                        blocks: None,
                        executed_in_block: None,
                        in_mempool: true,
                        first_seen: Some(get_current_time_in_seconds()),
                        data,
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

    // Get a block template for the new block work (mining)
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

    pub async fn get_block_header_template(&self, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_block_header_template_for_storage(&storage, address).await
    }

    // Generate a block header template without transactions
    pub async fn get_block_header_template_for_storage(&self, storage: &S, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        trace!("get block header template");
        let extra_nonce: [u8; EXTRA_NONCE_SIZE] = rand::thread_rng().gen::<[u8; EXTRA_NONCE_SIZE]>(); // generate random bytes
        let tips_set = storage.get_tips().await?;
        let mut tips = Vec::with_capacity(tips_set.len());
        for hash in tips_set {
            trace!("Tip found from storage: {}", hash);
            tips.push(hash);
        }

        let current_height = self.get_height();
        if tips.len() > 1 {
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, tips.iter()).await?.clone();
            debug!("Best tip selected for this block template is {}", best_tip);
            let mut selected_tips = Vec::with_capacity(tips.len());
            for hash in tips {
                if best_tip != hash {
                    if !self.validate_tips(storage, &best_tip, &hash).await? {
                        debug!("Tip {} is invalid, not selecting it because difficulty can't be less than 91% of {}", hash, best_tip);
                        continue;
                    }

                    let distance = self.calculate_distance_from_mainchain(storage, &hash).await?;
                    debug!("Distance from mainchain for tip {} is {}", hash, distance);
                    if distance <= current_height && current_height - distance >= STABLE_LIMIT {
                        debug!("Tip {} is not selected for mining: too far from mainchain (distance: {}, height: {})", hash, distance, current_height);
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

        let mut sorted_tips = blockdag::sort_tips(storage, tips.into_iter()).await?;
        if sorted_tips.len() > TIPS_LIMIT {
            let dropped_tips = sorted_tips.drain(TIPS_LIMIT..); // keep only first 3 heavier tips
            for hash in dropped_tips {
                debug!("Dropping tip {} because it is not in the first 3 heavier tips", hash);
            }
        }

        let height = blockdag::calculate_height_at_tips(storage, sorted_tips.iter()).await?;
        let block = BlockHeader::new(self.get_version_at_height(height), height, get_current_time_in_millis(), sorted_tips, extra_nonce, address, IndexSet::new());

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

        // use the mempool cache to get all availables txs grouped by account
        let caches = mempool.get_caches();
        let mut entries: Vec<Vec<TxSelectorEntry>> = Vec::with_capacity(caches.len());
        for cache in caches.values() {
            let cache_txs = cache.get_txs();
            let mut txs = Vec::with_capacity(cache_txs.len());
            // Map every tx hash to a TxSelectorEntry
            for tx_hash in cache_txs.iter() {
                let sorted_tx = mempool.get_sorted_tx(tx_hash)?;
                txs.push(TxSelectorEntry { size: sorted_tx.get_size(), hash: tx_hash, tx: sorted_tx.get_tx() });
            }
            entries.push(txs);
        }

        // Build the tx selector using the mempool
        let mut tx_selector = TxSelector::grouped(entries.into_iter());

        // size of block
        let mut block_size = block.size();
        let mut total_txs_size = 0;

        // data used to verify txs
        let topoheight = self.get_topo_height();
        trace!("build chain state for block template");
        let mut chain_state = ChainState::new(storage, topoheight);

        let mut failed_sources = HashSet::new();
        while let Some(TxSelectorEntry { size, hash, tx }) = tx_selector.next() {
            if block_size + total_txs_size + size >= MAX_BLOCK_SIZE {
                break;
            }

            // Check if the TX is valid for this potential block
            trace!("Checking TX {} with nonce {}, {}", hash, tx.get_nonce(), tx.get_source().as_address(self.network.is_mainnet()));
            let source = tx.get_source();
            if failed_sources.contains(&source) {
                debug!("Skipping TX {} because its source has failed before", hash);
                continue;
            }

            if let Err(e) = tx.verify(&mut chain_state).await {
                warn!("TX {} ({}) is not valid for mining: {}", hash, source.as_address(self.network.is_mainnet()), e);
                failed_sources.insert(source);
            } else {
                trace!("Selected {} (nonce: {}, fees: {}) for mining", hash, tx.get_nonce(), format_xelis(tx.get_fee()));
                // TODO no clone
                block.txs_hashes.insert(hash.as_ref().clone());
                block_size += HASH_SIZE; // add the hash size
                total_txs_size += size;
            }
        }

        Ok(block)
    }

    // Build a block using the header and search for TXs in mempool and storage
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

    // Add a new block in chain
    pub async fn add_new_block(&self, block: Block, broadcast: bool, mining: bool) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.add_new_block_for_storage(&mut storage, block, broadcast, mining).await
    }

    // Add a new block in chain using the requested storage
    pub async fn add_new_block_for_storage(&self, storage: &mut S, block: Block, broadcast: bool, mining: bool) -> Result<(), BlockchainError> {
        let start = Instant::now();

        // Verify that the block is on the correct version
        if block.get_version() != self.get_version_at_height(block.get_height()) {
            return Err(BlockchainError::InvalidBlockVersion)
        }

        let block_hash = block.hash();
        debug!("Add new block {}", block_hash);
        if storage.has_block_with_hash(&block_hash).await? {
            debug!("Block {} is already in chain!", block_hash);
            return Err(BlockchainError::AlreadyInChain)
        }

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
            return Err(BlockchainError::InvalidTipsCount(block_hash, tips_count))
        }

        let current_height = self.get_height();
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
            return Err(BlockchainError::InvalidTipsCount(block_hash, tips_count))
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
                return Err(BlockchainError::InvalidTipsNotFound(block_hash, tip.clone()))
            }
        }

        let block_height_by_tips = blockdag::calculate_height_at_tips(storage, block.get_tips().iter()).await?;
        if block_height_by_tips != block.get_height() {
            debug!("Invalid block height {}, expected {} for this block {}", block.get_height(), block_height_by_tips, block_hash);
            return Err(BlockchainError::InvalidBlockHeight(block_height_by_tips, block.get_height()))
        }

        let stable_height = self.get_stable_height();
        if tips_count > 0 {
            debug!("Height by tips: {}, stable height: {}", block_height_by_tips, stable_height);

            if block_height_by_tips < stable_height {
                debug!("Invalid block height by tips {} for this block ({}), its height is in stable height {}", block_height_by_tips, block_hash, stable_height);
                return Err(BlockchainError::InvalidBlockHeightStableHeight)
            }
        }

        if !self.verify_non_reachability(storage, block.get_tips()).await? {
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
            let distance = self.calculate_distance_from_mainchain(storage, hash).await?;
            if distance <= current_height && current_height - distance >= STABLE_LIMIT {
                debug!("{} with hash {} have deviated too much, maximum allowed is {} (current height: {}, distance: {})", block, block_hash, STABLE_LIMIT, current_height, distance);
                return Err(BlockchainError::BlockDeviation)
            }
        }

        if tips_count > 1 {
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, block.get_tips().iter()).await?;
            debug!("Best tip selected for this new block is {}", best_tip);
            for hash in block.get_tips() {
                if best_tip != hash {
                    if !self.validate_tips(storage, best_tip, hash).await? {
                        debug!("Tip {} is invalid, difficulty can't be less than 91% of {}", hash, best_tip);
                        return Err(BlockchainError::InvalidTipsDifficulty(block_hash, hash.clone()))
                    }
                }
            }
        }

        // verify PoW and get difficulty for this block based on tips
        let pow_hash = block.get_pow_hash()?;
        debug!("POW hash: {}", pow_hash);
        let (difficulty, p) = self.verify_proof_of_work(storage, &pow_hash, block.get_tips().iter()).await?;
        debug!("PoW is valid for difficulty {}", difficulty);

        let mut current_topoheight = self.get_topo_height();
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
                debug!("Block {} has an invalid block header, transaction count mismatch (expected {} got {})!", block_hash, txs_len, hashes_len);
                return Err(BlockchainError::InvalidBlockTxs(hashes_len, txs_len));
            }

            trace!("verifying {} TXs in block {}", txs_len, block_hash);
            let mut chain_state = ChainState::new(storage, current_topoheight);
            // Cache to retrieve only one time all TXs hashes until stable height
            let mut all_parents_txs: Option<HashSet<Hash>> = None;
            let mut batch = Vec::with_capacity(block.get_txs_count());
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
                // check that the TX included is not executed in stable height or in block TIPS
                if chain_state.get_storage().is_tx_executed_in_a_block(hash)? {
                    let block_executed = chain_state.get_storage().get_block_executor_for_tx(hash)?;
                    debug!("Tx {} was executed in {}", hash, block_executed);
                    let block_height = chain_state.get_storage().get_height_for_block_hash(&block_executed).await?;
                    // if the tx was executed below stable height, reject whole block!
                    if block_height <= stable_height {
                        debug!("Block {} contains a dead tx {}", block_hash, tx_hash);
                        return Err(BlockchainError::DeadTx(tx_hash))
                    } else {
                        debug!("Tx {} was executed in block {} at height {} (stable height: {})", tx_hash, block, block_height, stable_height);
                        // now we should check that the TX was not executed in our TIP branch
                        // because that mean the miner was aware of the TX execution and still include it
                        if all_parents_txs.is_none() {
                            // load it only one time
                            all_parents_txs = Some(self.get_all_executed_txs_until_height(chain_state.get_storage(), stable_height, block.get_tips().iter().map(Hash::clone)).await?);
                        }

                        // if its the case, we should reject the block
                        if let Some(txs) = all_parents_txs.as_ref() {
                            // miner knows this tx was already executed because its present in block tips
                            // reject the whole block
                            if txs.contains(&tx_hash) {
                                debug!("Malicious Block {} formed, contains a dead tx {}", block_hash, tx_hash);
                                return Err(BlockchainError::DeadTx(tx_hash))
                            } else {
                                // otherwise, all looks good but because the TX was executed in another branch, we skip verification
                                // DAG will choose which branch will execute the TX
                                debug!("TX {} was executed in another branch, skipping verification", tx_hash);

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

                batch.push(tx);
            }

            trace!("proof verifications of {} TXs in block {}", batch.len(), block_hash);
            // Verify all valid transactions in one batch
            Transaction::verify_batch(batch.as_slice(), &mut chain_state).await?;
        }

        // Save transactions & block
        let (block, txs) = block.split();
        let block = block.to_arc();
        debug!("Saving block {} on disk", block_hash);
        // Add block to chain
        storage.save_block(block.clone(), &txs, difficulty, p, block_hash.clone()).await?;

        // Compute cumulative difficulty for block
        let cumulative_difficulty = {
            let cumulative_difficulty: CumulativeDifficulty = if tips_count == 0 {
                GENESIS_BLOCK_DIFFICULTY.into()
            } else {
                let (base, base_height) = self.find_common_base(storage, block.get_tips()).await?;
                let (_, cumulative_difficulty) = self.find_tip_work_score::<S>(&storage, &block_hash, &base, base_height).await?;
                cumulative_difficulty
            };
            storage.set_cumulative_difficulty_for_block_hash(&block_hash, cumulative_difficulty).await?;
            debug!("Cumulative difficulty for block {}: {}", block_hash, cumulative_difficulty);
            cumulative_difficulty
        };

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

        // track all events to notify websocket
        let mut events: HashMap<NotifyEvent, Vec<Value>> = HashMap::new();
        // Track all orphaned tranasctions
        let mut orphaned_transactions = HashSet::new();

        // order the DAG (up to TOP_HEIGHT - STABLE_LIMIT)
        let mut highest_topo = 0;
        // Tells if the new block added is ordered in DAG or not
        let block_is_ordered = full_order.contains(&block_hash);
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
                        if let Some(order) = full_order.first() {
                            // Verify that the block is still at the same topoheight
                            if storage.is_block_topological_ordered(order).await && *order == hash_at_topo {
                                trace!("Hash {} at topo {} stay the same, skipping cleaning", hash_at_topo, topoheight);
                                // remove the hash from the order because we don't need to recompute it
                                full_order.shift_remove_index(0);
                                topoheight += 1;
                                skipped += 1;
                                continue;
                            }
                        }
                        // if we are here, it means that the block was re-ordered
                        is_written = true;
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
                        if storage.is_tx_executed_in_block(tx_hash, &hash_at_topo)? {
                            trace!("Removing execution of {}", tx_hash);
                            storage.remove_tx_executed(&tx_hash)?;

                            if is_orphaned {
                                orphaned_transactions.insert(tx_hash.clone());
                            }
                        }
                    }

                    // Delete changes made by this block
                    storage.delete_versioned_balances_at_topoheight(topoheight).await?;
                    storage.delete_versioned_nonces_at_topoheight(topoheight).await?;
                    storage.delete_registrations_at_topoheight(topoheight).await?;

                    topoheight += 1;
                }
            }

            // This is used to verify that each nonce is used only one time
            let mut nonce_checker = NonceChecker::new();
            // Side blocks counter per height
            let mut side_blocks: HashMap<u64, u64> = HashMap::new();
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

                // Block for this hash
                let block = storage.get_block_by_hash(&hash).await?;

                // Reward the miner of this block
                // We have a decreasing block reward if there is too much side block
                let is_side_block = self.is_side_block_internal(storage, &hash, highest_topo).await?;
                let height = block.get_height();
                let side_blocks_count = match side_blocks.entry(height) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let mut count = 0;
                        let blocks_at_height = storage.get_blocks_at_height(height).await?;
                        for block in blocks_at_height {
                            if block != hash && self.is_side_block_internal(storage, &block, highest_topo).await? {
                                count += 1;
                                debug!("Found side block {} at height {}", block, height);
                            }
                        }

                        entry.insert(count)
                    },
                };

                let mut block_reward = self.internal_get_block_reward(past_supply, is_side_block, *side_blocks_count).await?;
                trace!("set block {} reward to {} at {} (height {}, side block: {}, {} {}%)", hash, block_reward, highest_topo, height, is_side_block, side_blocks_count, side_block_reward_percentage(*side_blocks_count));
                if is_side_block {
                    *side_blocks_count += 1;
                }

                storage.set_block_reward_at_topo_height(highest_topo, block_reward)?;
                
                let supply = past_supply + block_reward;
                trace!("set block supply to {} at {}", supply, highest_topo);
                storage.set_supply_at_topo_height(highest_topo, supply)?;

                // All fees from the transactions executed in this block
                let mut total_fees = 0;
                // Chain State used for the verification
                trace!("building chain state to execute TXs in block {}", block_hash);
                let mut chain_state = ApplicableChainState::new(storage, highest_topo);

                // compute rewards & execute txs
                for (tx, tx_hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) { // execute all txs
                    // Link the transaction hash to this block
                    if !chain_state.get_mut_storage().add_block_linked_to_tx_if_not_present(&tx_hash, &hash)? {
                        trace!("Block {} is now linked to tx {}", hash, tx_hash);
                    }

                    // check that the tx was not yet executed in another tip branch
                    if chain_state.get_storage().is_tx_executed_in_a_block(tx_hash)? {
                        trace!("Tx {} was already executed in a previous block, skipping...", tx_hash);
                    } else {
                        // tx was not executed, but lets check that it is not a potential double spending
                        // check that the nonce is not already used
                        if !nonce_checker.use_nonce(chain_state.get_storage(), tx.get_source(), tx.get_nonce(), highest_topo).await? {
                            warn!("Malicious TX {}, it is a potential double spending with same nonce {}, skipping...", tx_hash, tx.get_nonce());
                            // TX will be orphaned
                            continue;
                        }

                        // Execute the transaction by applying changes in storage
                        debug!("Executing tx {} in block {} with nonce {}", tx_hash, hash, tx.get_nonce());
                        if let Err(e) = tx.apply_with_partial_verify(chain_state.as_mut()).await {
                            warn!("Error while executing TX {} with current DAG org: {}", tx_hash, e);
                            // TX may be orphaned if not added again in good order in next blocks
                            continue;
                        }

                        // Calculate the new nonce
                        // This has to be done in case of side blocks where TX B would be before TX A
                        let next_nonce = nonce_checker.get_new_nonce(tx.get_source(), self.network.is_mainnet())?;
                        chain_state.as_mut().update_account_nonce(tx.get_source(), next_nonce).await?;

                        // mark tx as executed
                        chain_state.get_mut_storage().set_tx_executed_in_block(tx_hash, &hash)?;

                        // Delete the transaction from  the list if it was marked as orphaned
                        if orphaned_transactions.remove(&tx_hash) {
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

                        // Increase total tx fees for miner
                        total_fees += tx.get_fee();
                    }
                }

                let dev_fee_percentage = get_block_dev_fee(block.get_height());
                // Dev fee are only applied on block reward
                // Transaction fees are not affected by dev fee
                if dev_fee_percentage != 0 {
                    let dev_fee_part = block_reward * dev_fee_percentage / 100;
                    chain_state.reward_miner(&DEV_PUBLIC_KEY, dev_fee_part).await?;
                    block_reward -= dev_fee_part;    
                }
                
                // reward the miner
                chain_state.reward_miner(block.get_miner(), block_reward + total_fees).await?;

                // apply changes from Chain State
                chain_state.apply_changes().await?;

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
        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, new_tips.iter()).await?.clone();
        for hash in new_tips {
            if best_tip != hash {
                if !self.validate_tips::<S>(&storage, &best_tip, &hash).await? {
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

        // If block is directly orphaned
        // Mark all TXs ourself as linked to it
        if !block_is_ordered {
            trace!("Block {} is orphaned, marking all TXs as linked to it", block_hash);
            for tx_hash in block.get_txs_hashes() {
                storage.add_block_linked_to_tx_if_not_present(&tx_hash, &block_hash)?;
            }
        }

        // auto prune mode
        if extended {
            if let Some(keep_only) = self.auto_prune_keep_n_blocks {
                // check that the topoheight is greater than the safety limit
                // and that we can prune the chain using the config while respecting the safety limit
                if current_topoheight % keep_only == 0 && current_topoheight - keep_only > 0 {
                    info!("Auto pruning chain until topoheight {} (keep only {} blocks)", current_topoheight - keep_only, keep_only);
                    if let Err(e) = self.prune_until_topoheight_for_storage(current_topoheight - keep_only, storage).await {
                        warn!("Error while trying to auto prune chain: {}", e);
                    }
                }
            }
        }

        // Store the new tips available
        storage.store_tips(&tips)?;

        let mut current_height = current_height;
        if current_height == 0 || block.get_height() > current_height {
            debug!("storing new top height {}", block.get_height());
            storage.set_top_height(block.get_height())?;
            self.height.store(block.get_height(), Ordering::Release);
            current_height = block.get_height();
        }

        // update stable height and difficulty in cache
        {
            let (stable_hash, stable_height) = self.find_common_base::<S, _>(&storage, &tips).await?;
            if should_track_events.contains(&NotifyEvent::StableHeightChanged) {
                // detect the change in stable height
                let previous_stable_height = self.get_stable_height();
                if stable_height != previous_stable_height {
                    let value = json!(StableHeightChangedEvent {
                        previous_stable_height,
                        new_stable_height: stable_height
                    });
                    events.entry(NotifyEvent::StableHeightChanged).or_insert_with(Vec::new).push(value);
                }
            }

            // Update caches
            self.stable_height.store(stable_height, Ordering::SeqCst);
            // Search the topoheight of the stable block
            let stable_topoheight = storage.get_topo_height_for_hash(&stable_hash).await?;
            self.stable_topoheight.store(stable_topoheight, Ordering::SeqCst);

            trace!("update difficulty in cache");
            let (difficulty, _) = self.get_difficulty_at_tips(storage, tips.iter()).await?;
            self.set_difficulty(difficulty).await;
        }

        // Check if the event is tracked
        let orphan_event_tracked = should_track_events.contains(&NotifyEvent::TransactionOrphaned);

        // Clean mempool from old txs
        let mempool_deleted_txs = {
            debug!("Locking mempool write mode");
            let mut mempool = self.mempool.write().await;
            debug!("mempool write mode ok");
            mempool.clean_up(&*storage, highest_topo).await
        };

        if orphan_event_tracked {
            for (tx_hash, sorted_tx) in mempool_deleted_txs {
                // Delete it from our orphaned transactions list
                // This save some performances as it will not try to add it back and
                // consume resources for verifying the ZK Proof if we already know the answer
                if orphaned_transactions.remove(&tx_hash) {
                    trace!("Transaction {} was marked as orphaned, but got deleted from mempool. Prevent adding it back", tx_hash);
                }
                // Verify that the TX was not executed in a block
                if storage.is_tx_executed_in_a_block(&tx_hash)? {
                    continue;
                }

                let data = RPCTransaction::from_tx(&sorted_tx.get_tx(), &tx_hash, storage.is_mainnet());
                let data = TransactionResponse {
                    blocks: None,
                    executed_in_block: None,
                    in_mempool: false,
                    first_seen: Some(sorted_tx.get_first_seen()),
                    data,
                };
                events.entry(NotifyEvent::TransactionOrphaned).or_insert_with(Vec::new).push(json!(data));
            }
        }

        // Now we can try to add back all transactions
        for tx_hash in orphaned_transactions {
            debug!("Adding back orphaned tx {}", tx_hash);
            // It is verified in add_tx_to_mempool function too
            // But to prevent loading the TX from storage and to fire wrong event
            if !storage.is_tx_executed_in_a_block(&tx_hash)? {
                let tx = match storage.get_transaction(&tx_hash).await {
                    Ok(tx) => tx,
                    Err(e) => {
                        warn!("Error while loading orphaned tx: {}", e);
                        continue;
                    }
                };

                // Clone only if its necessary
                if !orphan_event_tracked {
                    if let Err(e) = self.add_tx_to_mempool_with_storage_and_hash(&storage, tx, tx_hash, false).await {
                        debug!("Error while adding back orphaned tx: {}", e);
                    }
                } else {
                    if let Err(e) = self.add_tx_to_mempool_with_storage_and_hash(&storage, tx.clone(), tx_hash.clone(), false).await {
                        debug!("Error while adding back orphaned tx: {}, broadcasting event", e);
                        // We couldn't add it back to mempool, let's notify this event
                        if should_track_events.contains(&NotifyEvent::TransactionOrphaned) {
                            let data = RPCTransaction::from_tx(&tx, &tx_hash, storage.is_mainnet());

                            let data = TransactionResponse {
                                blocks: None,
                                executed_in_block: None,
                                in_mempool: false,
                                first_seen: None,
                                data,
                            };
                            events.entry(NotifyEvent::TransactionOrphaned).or_insert_with(Vec::new).push(json!(data));
                        }
                    }
                }
            }
        }

        info!("Processed block {} at height {} in {:?} with {} txs (DAG: {})", block_hash, block.get_height(), start.elapsed(), block.get_txs_count(), block_is_ordered);

        // Broadcast to p2p nodes
        if broadcast {
            trace!("Broadcasting block");
            if let Some(p2p) = self.p2p.read().await.as_ref() {
                trace!("P2p locked, broadcasting in new task");
                let p2p = p2p.clone();
                let pruned_topoheight = storage.get_pruned_topoheight().await?;
                let block = block.clone();
                let block_hash = block_hash.clone();
                tokio::spawn(async move {
                    p2p.broadcast_block(&block, cumulative_difficulty, current_topoheight, current_height, pruned_topoheight, &block_hash, mining).await;
                });
            }
        }

        // broadcast to websocket new block
        if let Some(rpc) = rpc_server.as_ref() {
            // if we have a getwork server, and that its not from syncing, notify miners
            if broadcast {
                if let Some(getwork) = rpc.getwork_server() {
                    let getwork = getwork.clone();
                    tokio::spawn(async move {
                        if let Err(e) = getwork.notify_new_job().await {
                            debug!("Error while notifying new job to miners: {}", e);
                        }
                    });
                }
            }

            // atm, we always notify websocket clients
            trace!("Notifying websocket clients");
            if should_track_events.contains(&NotifyEvent::NewBlock) {
                match get_block_response(self, storage, &block_hash, &Block::new(Immutable::Arc(block), txs), block_size).await {
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

    // Get block reward based on the type of the block
    // Block shouldn't be orphaned
    pub async fn internal_get_block_reward(&self, past_supply: u64, is_side_block: bool, side_blocks_count: u64) -> Result<u64, BlockchainError> {
        trace!("internal get block reward");
        let block_reward = if is_side_block {
            let reward = get_block_reward(past_supply);
            let side_block_percent = side_block_reward_percentage(side_blocks_count);
            trace!("side block reward: {}%", side_block_percent);

            reward * side_block_percent / 100
        } else {
            get_block_reward(past_supply)
        };
        Ok(block_reward)
    }

    // Get the block reward for a block
    // This will search all blocks at same height and verify which one are side blocks
    pub async fn get_block_reward(&self, storage: &S, hash: &Hash, past_supply: u64, current_topoheight: u64) -> Result<u64, BlockchainError> {
        let is_side_block = self.is_side_block(storage, hash).await?;
        let mut side_blocks_count = 0;
        if is_side_block {
            // get the block height for this hash
            let height = storage.get_height_for_block_hash(hash).await?;
            let blocks_at_height = storage.get_blocks_at_height(height).await?;
            for block in blocks_at_height {
                if *hash != block && self.is_side_block_internal(storage, &block, current_topoheight).await? {
                    side_blocks_count += 1;
                }
            }
        }

        self.internal_get_block_reward(past_supply, is_side_block, side_blocks_count).await
    }

    // retrieve all txs hashes until height or until genesis block that were executed in a block
    // for this we get all tips and recursively retrieve all txs from tips until we reach height
    async fn get_all_executed_txs_until_height<P>(&self, provider: &P, until_height: u64, tips: impl Iterator<Item = Hash>) -> Result<HashSet<Hash>, BlockchainError>
    where
        P: DifficultyProvider + ClientProtocolProvider
    {
        trace!("get all txs until height {}", until_height);
        // All transactions hashes found under the stable height
        let mut hashes = HashSet::new();
        // Current queue of blocks to process
        let mut queue = IndexSet::new();
        // All already processed blocks
        let mut processed = IndexSet::new();
        queue.extend(tips);

        // get last element from queue (order doesn't matter and its faster than moving all elements)
        while let Some(hash) = queue.pop() {
            let block = provider.get_block_header_by_hash(&hash).await?;

            // check that the block height is higher than the height passed in param
            if until_height < block.get_height() {
                // add all txs from block
                for tx in block.get_txs_hashes() {
                    // Check that we don't have it yet
                    if !hashes.contains(tx) {
                        // Then check that it's executed in this block
                        if provider.is_tx_executed_in_block(tx, &hash)? {
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
    pub async fn is_block_orphaned_for_storage(&self, storage: &S, hash: &Hash) -> bool {
        trace!("is block {} orphaned", hash);
        !storage.is_block_topological_ordered(hash).await
    }

    pub async fn is_side_block(&self, storage: &S, hash: &Hash) -> Result<bool, BlockchainError> {
        self.is_side_block_internal(storage, hash, self.get_topo_height()).await
    }

    // a block is a side block if its ordered and its block height is less than or equal to height of past 8 topographical blocks
    pub async fn is_side_block_internal<P>(&self, provider: &P, hash: &Hash, current_topoheight: u64) -> Result<bool, BlockchainError>
    where
        P: DifficultyProvider + DagOrderProvider
    {
        trace!("is block {} a side block", hash);
        if !provider.is_block_topological_ordered(hash).await {
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
    pub async fn has_block_stable_order<P>(&self, provider: &P, hash: &Hash, topoheight: u64) -> Result<bool, BlockchainError>
    where
        P: DagOrderProvider
    {
        trace!("has block {} stable order at topoheight {}", hash, topoheight);
        if provider.is_block_topological_ordered(hash).await {
            let block_topo_height = provider.get_topo_height_for_hash(hash).await?;
            return Ok(block_topo_height + STABLE_LIMIT <= topoheight)
        }
        Ok(false)
    }

    // Rewind the chain by removing N blocks from the top
    pub async fn rewind_chain(&self, count: u64, until_stable_height: bool) -> Result<u64, BlockchainError> {
        let mut storage = self.storage.write().await;
        self.rewind_chain_for_storage(&mut storage, count, until_stable_height).await
    }

    // Rewind the chain by removing N blocks from the top
    pub async fn rewind_chain_for_storage(&self, storage: &mut S, count: u64, stop_at_stable_height: bool) -> Result<u64, BlockchainError> {
        trace!("rewind chain with count = {}", count);
        let current_height = self.get_height();
        let current_topoheight = self.get_topo_height();
        warn!("Rewind chain with count = {}, height = {}, topoheight = {}", count, current_height, current_topoheight);
        let until = if stop_at_stable_height {
            self.get_stable_height()
        } else {
            0
        };
        let (new_height, new_topoheight, txs) = storage.pop_blocks(current_height, current_topoheight, count, until).await?;
        debug!("New topoheight: {} (diff: {})", new_topoheight, current_topoheight - new_topoheight);

        // Try to add all txs back to mempool if possible
        // We try to prevent lost/to be orphaned
        {
            for (hash, tx) in txs {
                debug!("Trying to add TX {} to mempool again", hash);
                if let Err(e) = self.add_tx_to_mempool_with_storage_and_hash(storage, tx, hash, false).await {
                    debug!("TX rewinded is not compatible anymore: {}", e);
                }
            }
        }

        self.height.store(new_height, Ordering::Release);
        self.topoheight.store(new_topoheight, Ordering::Release);
        // update stable height if it's allowed
        if !stop_at_stable_height {
            let tips = storage.get_tips().await?;
            let (stable_hash, stable_height) = self.find_common_base::<S, _>(&storage, &tips).await?;

            // if we have a RPC server, propagate the StableHeightChanged if necessary
            if let Some(rpc) = self.rpc.read().await.as_ref() {
                let previous_stable_height = self.get_stable_height();
                if stable_height != previous_stable_height {
                    if rpc.is_event_tracked(&NotifyEvent::StableHeightChanged).await {
                        let rpc = rpc.clone();
                        tokio::spawn(async move {
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
            }
            self.stable_height.store(stable_height, Ordering::SeqCst);
            let stable_topoheight = storage.get_topo_height_for_hash(&stable_hash).await?;
            self.stable_topoheight.store(stable_topoheight, Ordering::SeqCst);
        }

        Ok(new_topoheight)
    }

    // Calculate the average block time on the last 50 blocks
    // It will return the target block time if we don't have enough blocks
    // We calculate it by taking the timestamp of the block at topoheight - 50 and the timestamp of the block at topoheight
    // It is the same as computing the average time between the last 50 blocks but much faster
    // Genesis block timestamp isn't take in count for this calculation
    pub async fn get_average_block_time<P>(&self, provider: &P) -> Result<TimestampMillis, BlockchainError>
    where
        P: DifficultyProvider + PrunedTopoheightProvider + DagOrderProvider
    {
        // current topoheight
        let topoheight = self.get_topo_height();

        // we need to get the block hash at topoheight - 50 to compare
        // if topoheight is 0, returns the target as we don't have any block
        // otherwise returns topoheight
        let mut count = if topoheight > 50 {
            50
        } else if topoheight <= 1 {
            return Ok(BLOCK_TIME_MILLIS);
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
}


// Estimate the required fees for a transaction
pub async fn estimate_required_tx_fees<P: AccountProvider>(provider: &P, current_topoheight: u64, tx: &Transaction) -> Result<u64, BlockchainError> {
    let mut output_count = 0;
    let mut new_addresses = 0;
    if let TransactionType::Transfers(transfers) = tx.get_data() {
        output_count = transfers.len();
        for transfer in transfers {
            if !provider.is_account_registered_below_topoheight(transfer.get_destination(), current_topoheight).await? {
                new_addresses += 1;
            }
        }
    }

    Ok(calculate_tx_fee(tx.size(), output_count, new_addresses))
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

// Calculate the block reward based on the current supply
pub fn get_block_reward(supply: u64) -> u64 {
    // Prevent any overflow
    if supply >= MAXIMUM_SUPPLY {
        // Max supply reached, do we want to generate small fixed amount of coins? 
        return 0
    }

    let base_reward = (MAXIMUM_SUPPLY - supply) >> EMISSION_SPEED_FACTOR;
    base_reward * BLOCK_TIME_MILLIS / MILLIS_PER_SECOND / 180
}

// Returns the fee percentage for a block at a given height
pub fn get_block_dev_fee(height: u64) -> u64 {
    for threshold in DEV_FEES.iter() {
        if height <= threshold.height {
            return threshold.fee_percentage
        }
    }

    0
}

// Compute the combined merkle root of the tips
// pub async fn build_merkle_tips_hash<'a, S: DifficultyProvider, I: Iterator<Item = &'a Hash> + ExactSizeIterator>(storage: &S, sorted_tips: I) -> Result<Hash, BlockchainError> {
//     let mut merkles = Vec::with_capacity(sorted_tips.len());
//     for hash in sorted_tips {
//         let mut merkle_builder = MerkleBuilder::new();
//         let header = storage.get_block_header_by_hash(hash).await?;
//         merkle_builder.add(hash);
//         merkle_builder.add(header.get_tips_merkle_hash());
//         merkles.push(merkle_builder.build());
//     }

//     Ok(get_combined_hash_for_tips(merkles.iter()))
// }

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
}