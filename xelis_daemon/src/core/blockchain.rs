use anyhow::Error;
use serde_json::{Value, json};
use xelis_common::{
    config::{DEFAULT_P2P_BIND_ADDRESS, P2P_DEFAULT_MAX_PEERS, DEFAULT_RPC_BIND_ADDRESS, DEFAULT_CACHE_SIZE, MAX_BLOCK_SIZE, EMISSION_SPEED_FACTOR, MAX_SUPPLY, DEV_FEE_PERCENT, GENESIS_BLOCK, TIPS_LIMIT, TIMESTAMP_IN_FUTURE_LIMIT, STABLE_LIMIT, GENESIS_BLOCK_HASH, MINIMUM_DIFFICULTY, GENESIS_BLOCK_DIFFICULTY, XELIS_ASSET, SIDE_BLOCK_REWARD_PERCENT, DEV_PUBLIC_KEY, BLOCK_TIME},
    crypto::{key::PublicKey, hash::{Hashable, Hash}},
    difficulty::{check_difficulty, calculate_difficulty},
    transaction::{Transaction, TransactionType, EXTRA_DATA_LIMIT_SIZE},
    globals::get_current_timestamp,
    block::{Block, BlockHeader, EXTRA_NONCE_SIZE},
    immutable::Immutable,
    serializer::Serializer, account::VersionedBalance, api::daemon::{NotifyEvent, DataHash, BlockOrderedEvent, TransactionExecutedEvent, BlockType}, network::Network
};
use crate::{p2p::P2pServer, rpc::{rpc::{get_block_response_for_hash, get_block_type_for_block}, DaemonRpcServer, SharedDaemonRpcServer}};
use super::storage::{Storage, DifficultyProvider};
use std::{sync::atomic::{Ordering, AtomicU64}, collections::hash_map::Entry, time::Duration, borrow::Cow};
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
    #[clap(short = 'o', long)]
    pub priority_nodes: Vec<String>,
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
    pub disable_p2p_server: bool
}

pub struct Blockchain {
    height: AtomicU64, // current block height
    topoheight: AtomicU64, // current topo height
    stable_height: AtomicU64, // current stable height
    mempool: RwLock<Mempool>, // mempool to retrieve/add all txs
    storage: RwLock<Storage>, // storage to retrieve/add blocks
    p2p: Mutex<Option<Arc<P2pServer>>>, // P2p module
    rpc: Mutex<Option<SharedDaemonRpcServer>>, // Rpc module
    difficulty: AtomicU64, // current difficulty
    // used to skip PoW verification
    simulator: bool,
    // current network type on which one we're using/connected to
    network: Network
}

impl Blockchain {
    pub async fn new(config: Config, network: Network) -> Result<Arc<Self>, Error> {
        if config.simulator && network != Network::Dev {
            error!("Impossible to enable simulator mode except in dev network!");
            return Err(BlockchainError::InvalidNetwork.into())
        }

        let use_cache = if config.cache_size > 0 {
            Some(config.cache_size)
        } else {
            None
        };

        let dir_path = if let Some(path) = config.dir_path {
            path
        } else {
            network.to_string().to_lowercase()
        };

        let storage = Storage::new(dir_path, use_cache, network)?;
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
            p2p: Mutex::new(None),
            rpc: Mutex::new(None),
            difficulty: AtomicU64::new(GENESIS_BLOCK_DIFFICULTY),
            simulator: config.simulator,
            network
        };

        // include genesis block
        if !on_disk {
            blockchain.create_genesis_block().await?;
        } else {
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
            let storage = blockchain.get_storage().read().await;
            let tips = storage.get_tips().await?;
            let (_, stable_height) = blockchain.find_common_base(&storage, &tips).await?;
            blockchain.stable_height.store(stable_height, Ordering::SeqCst);
        }

        let arc = Arc::new(blockchain);
        // create P2P Server
        if !config.disable_p2p_server && arc.network != Network::Dev  {
            info!("Starting P2p server...");
            match P2pServer::new(config.tag, config.max_peers, config.p2p_bind_address, Arc::clone(&arc), config.priority_nodes.is_empty()) {
                Ok(p2p) => {
                    for addr in config.priority_nodes {
                        let addr: SocketAddr = match addr.parse() {
                            Ok(addr) => addr,
                            Err(e) => {
                                error!("Error while parsing priority node: {}", e);
                                continue;
                            }
                        };
                        info!("Trying to connect to priority node: {}", addr);
                        p2p.try_to_connect_to_peer(addr, true);
                    }
                    *arc.p2p.lock().await = Some(p2p);
                },
                Err(e) => error!("Error while starting P2p server: {}", e)
            };
        }

        // create RPC Server
        {
            info!("Starting RPC server...");
            match DaemonRpcServer::new(config.rpc_bind_address, Arc::clone(&arc), config.disable_getwork_server).await {
                Ok(server) => *arc.rpc.lock().await = Some(server),
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
        let mut p2p = self.p2p.lock().await;
        if let Some(p2p) = p2p.take() {
            p2p.stop().await;
        }

        let mut rpc = self.rpc.lock().await;
        if let Some(rpc) = rpc.take() {
            rpc.stop().await;
        }
        info!("All modules are now stopped!");
    }

    // function to include the genesis block and register the public dev key.
    async fn create_genesis_block(&self) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;

        // register XELIS asset
        debug!("Registering XELIS asset: {}", XELIS_ASSET);
        storage.add_asset(&XELIS_ASSET).await?;

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
            let header = BlockHeader::new(0, get_current_timestamp(), Vec::new(), [0u8; EXTRA_NONCE_SIZE], DEV_PUBLIC_KEY.clone(), Vec::new());
            let block = Block::new(Immutable::Owned(header), Vec::new());
            info!("Genesis generated: {}", block.to_hex());
            block
        };

        // hardcode genesis block topoheight
        storage.set_topo_height_for_block(&genesis_block.hash(), 0).await?;
        storage.set_top_height(0)?;

        self.add_new_block_for_storage(&mut storage, genesis_block, false).await?;

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
        zelf.add_new_block(block, true).await?;
        info!("Mined a new block {} at height {}", hash, block_height);
        Ok(())
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

    pub async fn get_mempool_size(&self) -> usize {
        self.mempool.read().await.size()
    }

    pub async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_top_block_hash_for_storage(&storage).await
    }
    
    pub async fn get_top_block_hash_for_storage(&self, storage: &Storage) -> Result<Hash, BlockchainError> {
        storage.get_hash_at_topo_height(self.get_topo_height()).await
    }

    pub async fn has_block(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        let storage = self.storage.read().await;
        storage.has_block(hash).await
    }

    pub async fn is_block_sync(&self, storage: &Storage, hash: &Hash) -> Result<bool, BlockchainError> {
        let current_height = self.get_height();
        self.is_block_sync_at_height(storage, hash, current_height).await
    }

    async fn is_block_sync_at_height(&self, storage: &Storage, hash: &Hash, height: u64) -> Result<bool, BlockchainError> {
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
        let mut i = block_height - 1;
        let mut pre_blocks = HashSet::new();
        while i >= (block_height - STABLE_LIMIT) && i != 0 {
            let blocks = storage.get_blocks_at_height(i).await?;
            pre_blocks.extend(blocks);
            i -= 1;
        }

        let sync_block_cumulative_difficulty = storage.get_cumulative_difficulty_for_block(hash).await?;
        // if potential sync block has lower cumulative difficulty than one of past blocks, it is not a sync block
        for hash in pre_blocks {
            let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(&hash).await?;
            if cumulative_difficulty >= sync_block_cumulative_difficulty {
                return Ok(false)
            }
        }

        Ok(true)
    }

    // TODO: cache based on height/hash
    #[async_recursion]
    async fn find_tip_base(&self, storage: &Storage, hash: &Hash, height: u64) -> Result<(Hash, u64), BlockchainError> {
        let tips = storage.get_past_blocks_of(hash).await?;
        let tips_count = tips.len();
        if tips_count == 0 { // only genesis block can have 0 tips saved
            return Ok((hash.clone(), 0))
        }

        let mut bases = Vec::with_capacity(tips_count);
        for hash in tips.iter() {
            if self.is_block_sync_at_height(storage, hash, height).await? {
                let block_height = storage.get_height_for_block_hash(hash).await?;
                return Ok((hash.clone(), block_height))
            }
            bases.push(self.find_tip_base(storage, hash, height).await?);
        }

        if bases.is_empty() {
            return Err(BlockchainError::ExpectedTips)
        }

        // now we sort descending by height and return the last element deleted
        bases.sort_by(|(_, a), (_, b)| b.cmp(a));
        // assert!(bases[0].1 >= bases[bases.len() - 1].1);

        Ok(bases.remove(bases.len() - 1))
    }

    // find the common base (block hash and block height) of all tips
    async fn find_common_base<'a, I: IntoIterator<Item = &'a Hash> + Copy>(&self, storage: &Storage, tips: I) -> Result<(Hash, u64), BlockchainError> {
        let mut best_height = 0;
        // first, we check the best (highest) height of all tips
        for hash in tips.into_iter() {
            let height = storage.get_height_for_block_hash(hash).await?;
            if height > best_height {
                best_height = height;
            }
        }

        let mut bases = Vec::new();
        for hash in tips.into_iter() {
            bases.push(self.find_tip_base(storage, hash, best_height).await?);
        }

        
        // check that we have at least one value
        if bases.is_empty() {
            error!("bases list is empty");
            return Err(BlockchainError::ExpectedTips)
        }

        // sort it descending by height
        // a = 5, b = 6, b.cmp(a) -> Ordering::Greater
        bases.sort_by(|(_, a), (_, b)| b.cmp(a));
        // assert!(bases[0].1 >= bases[bases.len() - 1].1);

        // retrieve the first block hash with its height
        Ok(bases.remove(bases.len() - 1))
    }

    #[async_recursion] // TODO no recursion
    async fn build_reachability_recursive(&self, storage: &Storage, set: &mut HashSet<Hash>, hash: Hash, level: u64) -> Result<(), BlockchainError> {
        if level >= 2 * STABLE_LIMIT {
            trace!("Level limit reached, adding {}", hash);
            set.insert(hash);
        } else {
            trace!("Level {} reached with hash {}", level, hash);
            let tips = storage.get_past_blocks_of(&hash).await?;
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
    async fn verify_non_reachability(&self, storage: &Storage, block: &BlockHeader) -> Result<bool, BlockchainError> {
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
    async fn calculate_distance_from_mainchain_recursive(&self, storage: &Storage, set: &mut HashSet<u64>, hash: &Hash) -> Result<(), BlockchainError> {
        let tips = storage.get_past_blocks_of(hash).await?;
        for hash in tips.iter() {
            if storage.is_block_topological_ordered(hash).await {
                set.insert(storage.get_height_for_block_hash(hash).await?);
            } else {
                self.calculate_distance_from_mainchain_recursive(storage, set, hash).await?;
            }
        }
        Ok(())
    }

    async fn calculate_distance_from_mainchain(&self, storage: &Storage, hash: &Hash) -> Result<u64, BlockchainError> {
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
    async fn find_tip_work_score_internal<'a>(&self, storage: &Storage, map: &mut HashMap<Hash, u64>, hash: &'a Hash, base_topoheight: u64, base_height: u64) -> Result<(), BlockchainError> {
        let tips = storage.get_past_blocks_of(hash).await?;
        for hash in tips.iter() {
            if !map.contains_key(hash) {
                let is_ordered = storage.is_block_topological_ordered(hash).await;
                if !is_ordered || (is_ordered && storage.get_topo_height_for_hash(hash).await? >= base_topoheight) {
                    self.find_tip_work_score_internal(storage, map, hash, base_topoheight, base_height).await?;
                }
            }
        }

        map.insert(hash.clone(), storage.get_difficulty_for_block(hash)?);

        Ok(())
    }

    // TODO cache
    // find the sum of work done
    async fn find_tip_work_score(&self, storage: &Storage, hash: &Hash, base: &Hash, base_height: u64) -> Result<(HashMap<Hash, u64>, u64), BlockchainError> {
        let block = storage.get_block_header_by_hash(hash).await?;
        let mut map: HashMap<Hash, u64> = HashMap::new();
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
            map.insert(base.clone(), storage.get_cumulative_difficulty_for_block(base).await?);
        }
        map.insert(hash.clone(), storage.get_difficulty_for_block(hash)?);

        let mut score = 0;
        for value in map.values() {
            score += value;
        }

        Ok((map, score))
    }

    async fn find_best_tip<'a>(&self, storage: &Storage, tips: &'a HashSet<Hash>, base: &Hash, base_height: u64) -> Result<&'a Hash, BlockchainError> {
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
    #[async_recursion]
    async fn generate_full_order(&self, storage: &Storage, hash: &Hash, base: &Hash, base_topo_height: u64) -> Result<Vec<Hash>, BlockchainError> {
        let block_tips = storage.get_past_blocks_of(hash).await?;
        if block_tips.len() == 0 {
            return Ok(vec![GENESIS_BLOCK_HASH.clone()])
        }

        // if the block has been previously ordered, return it as base
        if hash == base {
            return Ok(vec![base.clone()])
        }

        let mut order: Vec<Hash> = Vec::new();
        let mut scores = Vec::new();
        for hash in block_tips.iter() {
            let is_ordered = storage.is_block_topological_ordered(hash).await;
            if !is_ordered || (is_ordered && storage.get_topo_height_for_hash(hash).await? >= base_topo_height) {
                let diff = storage.get_cumulative_difficulty_for_block(hash).await?;
                scores.push((hash, diff));
            }
        }

        blockdag::sort_descending_by_cumulative_difficulty(&mut scores);

        for (hash, _) in scores {
            let sub_order = self.generate_full_order(storage, hash, base, base_topo_height).await?;
            for order_hash in sub_order {
                if !order.contains(&order_hash) {
                    order.push(order_hash);
                }
            }
        }

        order.push(hash.clone());

        Ok(order)
    }

    // confirms whether the actual tip difficulty is withing 9% deviation with best tip (reference)
    async fn validate_tips(&self, storage: &Storage, best_tip: &Hash, tip: &Hash) -> Result<bool, BlockchainError> {
        let best_difficulty = storage.get_difficulty_for_block(best_tip)?;
        let block_difficulty = storage.get_difficulty_for_block(tip)?;

        Ok(best_difficulty * 91 / 100 < block_difficulty)
    }

    pub async fn get_difficulty_at_tips<D: DifficultyProvider>(&self, provider: &D, tips: &Vec<Hash>) -> Result<u64, BlockchainError> {
        if tips.len() == 0 { // Genesis difficulty
            return Ok(GENESIS_BLOCK_DIFFICULTY)
        }

        let height = blockdag::calculate_height_at_tips(provider, tips).await?;
        if height < 3 {
            return Ok(MINIMUM_DIFFICULTY)
        }

        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(provider, tips).await?;
        let biggest_difficulty = provider.get_difficulty_for_block(best_tip).await?;
        let best_tip_timestamp = provider.get_timestamp_for_block(best_tip).await?;

        let parent_tips = provider.get_past_blocks_of(best_tip).await?;
        let parent_best_tip = blockdag::find_best_tip_by_cumulative_difficulty(provider, &parent_tips).await?;
        let parent_best_tip_timestamp = provider.get_timestamp_for_block(parent_best_tip).await?;
 
        let difficulty = calculate_difficulty(parent_best_tip_timestamp, best_tip_timestamp, biggest_difficulty);
        Ok(difficulty)
    }

    pub fn get_difficulty(&self) -> u64 {
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

    pub fn get_p2p(&self) -> &Mutex<Option<Arc<P2pServer>>> {
        &self.p2p
    }

    pub fn get_rpc(&self) -> &Mutex<Option<SharedDaemonRpcServer>> {
        &self.rpc
    }

    pub fn get_storage(&self) -> &RwLock<Storage> {
        &self.storage
    }

    pub fn get_mempool(&self) -> &RwLock<Mempool> {
        &self.mempool
    }

    pub async fn add_tx_to_mempool(&self, tx: Transaction, broadcast: bool) -> Result<(), BlockchainError> {
        let hash = tx.hash();
        self.add_tx_with_hash_to_mempool(tx, hash, broadcast).await
    }

    pub async fn add_tx_with_hash_to_mempool(&self, tx: Transaction, hash: Hash, broadcast: bool) -> Result<(), BlockchainError> {
        let mut mempool = self.mempool.write().await;
        let storage = self.storage.read().await;
        self.add_tx_for_mempool(&storage, &mut mempool, tx, hash, broadcast).await
    }

    async fn add_tx_for_mempool<'a>(&'a self, storage: &Storage, mempool: &mut Mempool, tx: Transaction, hash: Hash, broadcast: bool) -> Result<(), BlockchainError> {
        if mempool.contains_tx(&hash) {
            return Err(BlockchainError::TxAlreadyInMempool(hash))
        }

        {
            // get the highest nonce for this owner
            let owner = tx.get_owner();
            let mut nonces = HashMap::new();
            let mut balances = HashMap::new();
            
            // list of potential TXs from same owner
            let mut owner_txs = Vec::new();
            let mempool_txs = mempool.get_txs();
            for (hash, tx) in mempool_txs {
                if tx.get_owner() == owner {
                    let nonce = nonces.entry(tx.get_owner()).or_insert(0);
                    // if the tx is in mempool, then the nonce should be valid.
                    if *nonce < tx.get_nonce() {
                        *nonce = tx.get_nonce();
                    }
                    owner_txs.push((hash, tx));
                }
            }

            // if the nonce of tx is N + 1, we increment it to let it pass
            // so we have multiple TXs from same owner in the same block
            if let Some(nonce) = nonces.get_mut(owner) {
                if *nonce + 1 == tx.get_nonce() {
                    *nonce += 1;
                    // compute balances of previous pending TXs
                    for (hash, tx) in owner_txs {
                        if tx.get_owner() == owner {
                            // we also need to pre-compute the balance of the owner
                            self.verify_transaction_with_hash(storage, tx, &hash, &mut balances, None, true).await?;
                        }
                    }
                }
            }

            self.verify_transaction_with_hash(&storage, &tx, &hash, &mut balances, Some(&mut nonces), false).await?
        }

        if broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                p2p.broadcast_tx_hash(&hash).await;
            }
        }

        let tx = Arc::new(tx);
        mempool.add_tx(hash.clone(), tx.clone())?;

        // broadcast to websocket this tx
        if let Some(rpc) = self.rpc.lock().await.as_ref() {
            let rpc = rpc.clone();
            tokio::spawn(async move {
                let data: DataHash<'_, Arc<Transaction>> = DataHash { hash: Cow::Owned(hash), data: Cow::Owned(tx) };
                if let Err(e) = rpc.notify_clients(&NotifyEvent::TransactionAddedInMempool, data).await {
                    debug!("Error while broadcasting event TransactionAddedInMempool to websocket: {}", e);
                }
            });
        }

        Ok(())
    }

    pub async fn get_block_template(&self, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_block_template_for_storage(&storage, address).await
    }

    pub async fn get_block_template_for_storage(&self, storage: &Storage, address: PublicKey) -> Result<BlockHeader, BlockchainError> {
        let extra_nonce: [u8; EXTRA_NONCE_SIZE] = rand::thread_rng().gen::<[u8; EXTRA_NONCE_SIZE]>(); // generate random bytes
        let tips_set = storage.get_tips().await?;
        let mut tips = Vec::with_capacity(tips_set.len());
        for hash in tips_set {
            tips.push(hash);
        }

        let mut sorted_tips = blockdag::sort_tips(&storage, &tips).await?;
        sorted_tips.truncate(TIPS_LIMIT); // keep only first 3 heavier tips
        let height = blockdag::calculate_height_at_tips(storage, &tips).await?;
        let mut block = BlockHeader::new(height, get_current_timestamp(), sorted_tips, extra_nonce, address, Vec::new());

        let mempool = self.mempool.read().await;
        let txs = mempool.get_sorted_txs();
        let mut tx_size = 0;
        let mut nonces: HashMap<&PublicKey, u64> = HashMap::new();
        for tx in txs {
            if block.size() + tx_size + tx.get_size() > MAX_BLOCK_SIZE {
                break;
            }

            let transaction = mempool.view_tx(tx.get_hash())?;
            let account_nonce = if let Some(nonce) = nonces.get(transaction.get_owner()) {
                *nonce
            } else {
                let nonce = storage.get_nonce(transaction.get_owner()).await?;
                nonces.insert(transaction.get_owner(), nonce);
                nonce
            };

            if account_nonce < transaction.get_nonce() {
                debug!("Skipping {} with {} fees because another TX should be selected first due to nonce", tx.get_hash(), tx.get_fee());
            } else {
                // TODO no clone
                block.txs_hashes.push(tx.get_hash().clone());
                tx_size += tx.get_size();
                *nonces.get_mut(transaction.get_owner()).unwrap() += 1;
            }
        }
        Ok(block)
    }

    pub async fn build_block_from_header(&self, header: Immutable<BlockHeader>) -> Result<Block, BlockchainError> {
        let mut transactions: Vec<Immutable<Transaction>> = Vec::with_capacity(header.get_txs_count());
        let mempool = self.mempool.read().await;
        for hash in header.get_txs_hashes() {
            let tx = mempool.get_tx(hash)?; // at this point, we don't want to lose/remove any tx, we clone it only
            transactions.push(Immutable::Arc(tx));
        }
        let block = Block::new(header, transactions);
        Ok(block)
    }

    pub async fn add_new_block(&self, block: Block, broadcast: bool) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.add_new_block_for_storage(&mut storage, block, broadcast).await
    }

    pub async fn add_new_block_for_storage(&self, storage: &mut Storage, block: Block, broadcast: bool) -> Result<(), BlockchainError> {
        let block_hash = block.hash();
        if storage.has_block(&block_hash).await? {
            error!("Block is already in chain!");
            return Err(BlockchainError::AlreadyInChain)
        }

        if block.get_timestamp() > get_current_timestamp() + TIMESTAMP_IN_FUTURE_LIMIT { // accept 2s in future
            error!("Block timestamp in too much in future!");
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
            let previous_timestamp = storage.get_timestamp_for_block(hash).await?;
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
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(&*storage, block.get_tips()).await?;
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
        let difficulty = self.verify_proof_of_work(&*storage, &block_hash, block.get_tips()).await?;
        debug!("PoW is valid for difficulty {}", difficulty);

        let mut total_tx_size: usize = 0;
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
                if storage.has_tx_executed_in_block(hash)? {
                    let block_executed = storage.get_tx_executed_in_block(hash)?;
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
                                total_tx_size += tx.size();
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

                // increase the total size
                total_tx_size += tx.size();
                // add tx hash in cache
                cache_tx.insert(tx_hash, true);
            }

            if block.size() + total_tx_size > MAX_BLOCK_SIZE {
                error!("Block size ({} bytes) is greater than the limit ({} bytes)", block.size() + total_tx_size, MAX_BLOCK_SIZE);
                return Err(BlockchainError::InvalidBlockSize(MAX_BLOCK_SIZE, block.size() + total_tx_size));
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
            let cumulative_difficulty: u64 = if tips_count == 0 {
                GENESIS_BLOCK_DIFFICULTY
            } else {
                let (base, base_height) = self.find_common_base(storage, block.get_tips()).await?;
                let (_, cumulative_difficulty) = self.find_tip_work_score(&storage, &block_hash, &base, base_height).await?;
                cumulative_difficulty
            };
            storage.set_cumulative_difficulty_for_block(&block_hash, cumulative_difficulty).await?;
            debug!("Cumulative difficulty for block {}: {}", block_hash, cumulative_difficulty);
            cumulative_difficulty
        };

        // Delete all txs from mempool
        let mut mempool = self.mempool.write().await;
        for hash in block.get_txs_hashes() { // remove all txs present in mempool
            match mempool.remove_tx(hash) {
                Ok(_) => {
                    debug!("Removing tx hash '{}' from mempool", hash);
                },
                Err(_) => {}
            };
        }

        let mut tips = storage.get_tips().await?;
        tips.insert(block_hash.clone());
        for hash in block.get_tips() {
            tips.remove(hash);
        }

        let (base_hash, base_height) = self.find_common_base(storage, &tips).await?;
        let best_tip = self.find_best_tip(storage, &tips, &base_hash, base_height).await?;
        trace!("Best tip selected: {}", best_tip);

        let base_topo_height = storage.get_topo_height_for_hash(&base_hash).await?;
        // generate a full order until base_topo_height
        let mut full_order = self.generate_full_order(storage, &best_tip, &base_hash, base_topo_height).await?;
        trace!("Generated full order size: {}, with base ({}) topo height: {}", full_order.len(), base_hash, base_topo_height);

        // rpc server lock
        let rpc_server = self.rpc.lock().await;

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
            {
                let mut topoheight = base_topo_height;
                while topoheight <= current_topoheight {
                    let hash_at_topo = storage.get_hash_at_topo_height(topoheight).await?;
                    debug!("Cleaning txs at topoheight {} ({})", topoheight, hash_at_topo);
                    if !is_written {
                        if let Some(order) = full_order.get(0) {
                            if storage.is_block_topological_ordered(order).await && *order == hash_at_topo {
                                debug!("Hash {} at topo {} stay the same, skipping cleaning", hash_at_topo, topoheight);
                                // remove the hash from the order because we don't need to recompute it
                                full_order.remove(0);
                                topoheight += 1;
                                skipped += 1;
                                continue;
                            }
                        }
                        is_written = true;
                    }

                    debug!("Cleaning transactions executions at topo height {} (block {})", topoheight, hash_at_topo);

                    let block = storage.get_block_header_by_hash(&hash_at_topo).await?;

                    // mark txs as unexecuted
                    for tx_hash in block.get_txs_hashes() {
                        debug!("Removing execution of {}", tx_hash);
                        storage.remove_tx_executed(&tx_hash)?;
                    }

                    topoheight += 1;
                }
            }

            // time to order the DAG that is moving
            for (i, hash) in full_order.into_iter().enumerate() {
                highest_topo = base_topo_height + skipped + i as u64;

                // if block is not re-ordered and it's not genesis block
                // because we don't need to recompute everything as it's still good in chain
                if !is_written && tips_count != 0 && storage.is_block_topological_ordered(&hash).await && storage.get_topo_height_for_hash(&hash).await? == highest_topo {
                    trace!("Block ordered {} stay at topoheight {}. Skipping...", hash, highest_topo);
                    continue;
                }
                is_written = true;

                debug!("Ordering block {} at topoheight {}", hash, highest_topo);

                storage.set_topo_height_for_block(&hash, highest_topo).await?;
                let past_supply = if highest_topo == 0 {
                    0
                } else {
                    storage.get_supply_at_topo_height(highest_topo - 1).await?
                };

                let block_reward = if self.is_side_block(storage, &hash).await? {
                    debug!("Block {} at topoheight {} is a side block", hash, highest_topo);
                    let reward = get_block_reward(past_supply);
                    reward * SIDE_BLOCK_REWARD_PERCENT / 100
                } else {
                    get_block_reward(past_supply)
                };

                trace!("set block {} reward to {}", hash, block_reward);
                storage.set_block_reward(&hash, block_reward)?;
                trace!("set block {} supply to {}", hash, past_supply + block_reward);
                storage.set_supply_for_block(&hash, past_supply + block_reward)?;

                // track all changes in balances
                let mut balances: HashMap<&PublicKey, HashMap<&Hash, VersionedBalance>> = HashMap::new();
                let block = storage.get_block(&hash).await?;
                let mut total_fees = 0;

                // compute rewards & execute txs
                for (tx, tx_hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) { // execute all txs
                    // TODO improve it (too much read/write that can be refactored)
                    if !storage.has_block_linked_to_tx(&tx_hash, &hash)? {
                        storage.add_block_for_tx(&tx_hash, hash.clone())?;
                        debug!("Block {} is now linked to tx {}", hash, tx_hash);
                    }

                    // check that the tx was not yet executed in another tip branch
                    if storage.has_tx_executed_in_block(tx_hash)? {
                        debug!("Tx {} was already executed in a previous block, skipping...", tx_hash);
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
                        debug!("Executing tx {} in block {}", tx_hash, hash);
                        storage.set_tx_executed_in_block(tx_hash, &hash)?;

                        self.execute_transaction(storage, &tx, &mut nonces, &mut balances, highest_topo).await?;    
                        // if the rpc_server is enable, track events
                        if rpc_server.is_some() {
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

                // save nonces for each pubkey
                for (key, nonce) in &nonces {
                    trace!("Saving nonce {} for {}", nonce, key);
                    storage.set_nonce(key, *nonce).await?;
                }

                // save balances for each topoheight
                for (key, assets) in balances {
                    for (asset, balance) in assets {
                        trace!("Saving balance {} for {} at topo {}, previous: {:?}", asset, key, highest_topo, balance.get_previous_topoheight());
                        storage.set_balance_to(key, asset, highest_topo, &balance).await?;
                    }
                }

                if rpc_server.is_some() {
                    let event = NotifyEvent::BlockOrdered;
                    let value = json!(BlockOrderedEvent {
                        block_hash: Cow::Borrowed(&hash),
                        block_type: get_block_type_for_block(self, &storage, &hash).await.unwrap_or(BlockType::Normal),
                        topoheight: highest_topo,
                    });
                    events.entry(event).or_insert_with(Vec::new).push(value);
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
                // TODO rewind stale TIP
            }
        }

        tips = HashSet::new();
        debug!("find best tip by cumulative difficulty");
        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(&*storage, &new_tips).await?.clone();
        for hash in new_tips {
            if best_tip != hash {
                if !self.validate_tips(&storage, &best_tip, &hash).await? {
                    warn!("Rusty TIP {} declared stale", hash);
                    // TODO rewind stale TIP
                } else {
                    debug!("Tip {} is valid, adding to final Tips list", hash);
                    tips.insert(hash);
                }
            }
        }
        tips.insert(best_tip);

        // save highest topo height
        debug!("Highest topo height found: {}", highest_topo);
        if current_height == 0 || highest_topo > current_topoheight {
            debug!("Blockchain height extended, current topoheight is now {} (previous was {})", highest_topo, current_topoheight);
            storage.set_top_topoheight(highest_topo)?;
            self.topoheight.store(highest_topo, Ordering::Release);
            current_topoheight = highest_topo;
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
            debug!("Adding new '{}' {} with no topoheight (not ordered)!", block_hash, block);
        }

        // update stable height and difficulty in cache
        {
            let (_, height) = self.find_common_base(&storage, &tips).await?;
            self.stable_height.store(height, Ordering::SeqCst);

            trace!("update difficulty in cache");
            let mut tips_vec = Vec::with_capacity(tips.len());
            for hash in tips {
                tips_vec.push(hash);
            }
            let difficulty = self.get_difficulty_at_tips(&*storage, &tips_vec).await?;
            self.difficulty.store(difficulty, Ordering::SeqCst);
        }

        if broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                debug!("broadcast block to peers");
                p2p.broadcast_block(&block, cumulative_difficulty, current_topoheight, current_height, &block_hash).await;
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
            match get_block_response_for_hash(self, storage, block_hash, false).await {
                Ok(response) => {
                    events.entry(NotifyEvent::NewBlock).or_insert_with(Vec::new).push(response);
                },
                Err(e) => {
                    debug!("Error while getting block response for websocket: {}", e);
                }
            };

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

        // Clean all old txs
        mempool.clean_up(storage, nonces).await;

        Ok(())
    }

    // retrieve all txs hashes until height or until genesis block
    // for this we get all tips and recursively retrieve all txs from tips until we reach height
    async fn get_all_txs_until_height(&self, storage: &Storage, until_height: u64, tips: &Vec<Hash>) -> Result<HashSet<Hash>, BlockchainError> {
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
    pub async fn is_block_orphaned_for_storage(&self, storage: &Storage, hash: &Hash) -> bool {
        trace!("is block {} orphaned", hash);
        !storage.is_block_topological_ordered(hash).await
    }

    // a block is a side block if its ordered and its block height is less than or equal to height of past 8 topographical blocks
    pub async fn is_side_block(&self, storage: &Storage, hash: &Hash) -> Result<bool, BlockchainError> {
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
    pub async fn has_block_stable_order(&self, storage: &Storage, hash: &Hash, topoheight: u64) -> Result<bool, BlockchainError> {
        trace!("has block {} stable order at topoheight {}", hash, topoheight);
        if storage.is_block_topological_ordered(hash).await {
            let block_topo_height = storage.get_topo_height_for_hash(hash).await?;
            return Ok(block_topo_height + STABLE_LIMIT <= topoheight)
        }
        Ok(false)
    }

    pub async fn rewind_chain(&self, count: usize) -> Result<u64, BlockchainError> {
        let mut storage = self.storage.write().await;
        self.rewind_chain_for_storage(&mut storage, count).await
    }

    pub async fn rewind_chain_for_storage(&self, storage: &mut Storage, count: usize) -> Result<u64, BlockchainError> {
        trace!("rewind chain with count = {}", count);
        let current_height = self.get_height();
        let current_topoheight = self.get_topo_height();
        warn!("Rewind chain with count = {}, height = {}, topoheight = {}", count, current_height, current_topoheight);
        let (height, topoheight, txs, miners) = storage.pop_blocks(current_height, current_topoheight, count as u64).await?;
        debug!("New topoheight: {} (diff: {})", topoheight, current_topoheight - topoheight);
        // rewind all txs
        {
            let mut keys = HashSet::new();
            // merge miners keys
            for key in &miners {
                keys.insert(key);
            }

            // Add dev address in rewinding in case we receive dev fees
            if DEV_FEE_PERCENT != 0 {
                keys.insert(&DEV_PUBLIC_KEY);
            }

            let mut nonces = HashMap::new();
            let mut assets: HashSet<&Hash> = HashSet::new();
            // add native asset (because its necessary for fees)
            assets.insert(&XELIS_ASSET);

            for (hash, tx) in &txs {
                debug!("Rewinding tx hash: {}", hash);
                self.rewind_transaction(storage, tx, &mut keys, &mut nonces, &mut assets).await?;
            }

            // lowest previous versioned balances topoheight for each key
            let mut balances: HashMap<&PublicKey, HashMap<&Hash, Option<u64>>> = HashMap::new();
            // delete all versioned balances topoheight per topoheight
            for i in (topoheight..=current_topoheight).rev() {
                debug!("Clearing balances at topoheight {}", i);
                // do it for every keys detected
                for key in &keys {
                    for asset in &assets {
                        if storage.has_balance_at_exact_topoheight(key, asset, i).await? {
                            debug!("Deleting balance {} at topoheight {} for {}", asset, i, key);
                            let version = storage.delete_balance_at_topoheight(key, &asset, i).await?;
                            let previous = version.get_previous_topoheight();
                            debug!("Previous balance is {:?}", previous);
                            let assets = balances.entry(key).or_insert_with(HashMap::new);
                            assets.insert(asset, previous);
                        }
                    }
                }
            }

            // apply all changes: update last topoheight balances changes of each key 
            for (key, previous) in balances {
                for (asset, last) in previous {
                    match last {
                        Some(topo) => {
                            debug!("Set last topoheight balance for {} {} to {}", key, asset, topo);
                            storage.set_last_topoheight_for_balance(key, asset, topo)?;
                        },
                        None => {
                            debug!("delete last topoheight balance for {} {}", key, asset);
                            storage.delete_last_topoheight_for_balance(key, asset)?;
                        }
                    };
                }
            }

            // apply all changes to nonce
            for (key, nonce) in nonces {
                debug!("Set nonce for {} to {}", key, nonce);
                storage.set_nonce(key, nonce).await?;
            }

            debug!("Locking mempool");
            let mut mempool = self.mempool.write().await;
            for (hash, tx) in txs {
                debug!("Adding TX {} to mempool", hash);
                if let Err(e) = self.add_tx_for_mempool(&storage, &mut mempool, tx.as_ref().clone(), hash, false).await {
                    debug!("TX rewinded is not compatible anymore: {}", e);
                }
            }
        }
        self.height.store(height, Ordering::Release);
        self.topoheight.store(topoheight, Ordering::Release);
        // update stable height
        {
            let tips = storage.get_tips().await?;
            let (_, height) = self.find_common_base(&storage, &tips).await?;
            self.stable_height.store(height, Ordering::Release);
        }

        Ok(topoheight)
    }

    // verify the transaction and returns fees available
    // nonces allow us to support multiples tx from same owner in the same block
    // txs must be sorted in ascending order based on account nonce 
    async fn verify_transaction_with_hash<'a>(&self, storage: &Storage, tx: &'a Transaction, hash: &Hash, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, u64>>, nonces: Option<&mut HashMap<&'a PublicKey, u64>>, skip_nonces: bool) -> Result<(), BlockchainError> {
        trace!("Verify transaction with hash {}", hash);
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
                warn!("Overflow detected using fees in transaction {}", hash);
                return Err(BlockchainError::Overflow)
            }
        }

        match tx.get_data() {
            TransactionType::Transfer(txs) => {
                if txs.len() == 0 { // don't accept any empty tx
                    return Err(BlockchainError::TxEmpty(hash.clone()))
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
                        warn!("Overflow detected with transaction {}", hash);
                        return Err(BlockchainError::Overflow)
                    }
                }

                if extra_data_size > EXTRA_DATA_LIMIT_SIZE {
                    return Err(BlockchainError::InvalidTransactionExtraDataTooBig(EXTRA_DATA_LIMIT_SIZE, extra_data_size))   
                }
            }
            TransactionType::Burn(asset, amount) => {
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
                    warn!("Overflow detected with transaction {}", hash);
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
                            storage.get_nonce(tx.get_owner()).await?
                        } else {
                            0
                        };
                        entry.insert(nonce)
                    },
                    Entry::Occupied(entry) => entry.into_mut(),
                };
    
                if *nonce != tx.get_nonce() {
                    debug!("Tx {} has nonce {} but expected {}", hash, tx.get_nonce(), nonce);
                    return Err(BlockchainError::InvalidTxNonce)
                }
                // we increment it in case any new tx for same owner is following
                *nonce += 1;
            } else {
                let nonce = storage.get_nonce(tx.get_owner()).await?;
                if nonce != tx.get_nonce() {
                    return Err(BlockchainError::InvalidTxNonce)
                }
            }
        }

        Ok(())
    }

    // retrieve the already added balance with changes OR generate a new versioned balance
    async fn retrieve_balance<'a, 'b>(&self, storage: &Storage, balances: &'b mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, key: &'a PublicKey, asset: &'a Hash, topoheight: u64) -> Result<&'b mut VersionedBalance, BlockchainError> {
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
    async fn add_balance<'a>(&self, storage: &Storage, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, key: &'a PublicKey, asset: &'a Hash, amount: u64, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("add balance {} for {} at topoheight {} with {}", asset, key, topoheight, amount);
        let version = self.retrieve_balance(storage, balances, key, asset, topoheight).await?;
        version.add_balance(amount);
        Ok(())
    }

    // this function just subtract from balance
    // its used to centralize all computation
    async fn sub_balance<'a>(&self, storage: &Storage, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, key: &'a PublicKey, asset: &'a Hash, amount: u64, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("sub balance {} for {} at topoheight {} with {}", asset, key, topoheight, amount);
        let version = self.retrieve_balance(storage, balances, key, asset, topoheight).await?;
        version.sub_balance(amount);
        Ok(())
    }

    // reward block miner and dev fees if any.
    async fn reward_miner<'a>(&self, storage: &Storage, block: &'a BlockHeader, mut block_reward: u64, total_fees: u64, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, topoheight: u64) -> Result<(), BlockchainError> {
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

    async fn execute_transaction<'a>(&self, storage: &mut Storage, transaction: &'a Transaction, nonces: &mut HashMap<PublicKey, u64>, balances: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>, topoheight: u64) -> Result<(), BlockchainError> {
        let mut total_deducted: HashMap<&'a Hash, u64> = HashMap::new();
        total_deducted.insert(&XELIS_ASSET, transaction.get_fee());

        match transaction.get_data() {
            TransactionType::Burn(asset, amount) => {
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

    // rewind a transaction, save all keys used in a TX (sender / receiver) and update nonces with the lowest available
    async fn rewind_transaction<'a>(&self, _: &mut Storage, transaction: &'a Transaction, keys: &mut HashSet<&'a PublicKey>, nonces: &mut HashMap<&'a PublicKey, u64>, assets: &mut HashSet<&'a Hash>) -> Result<(), BlockchainError> {
        // add sender
        keys.insert(transaction.get_owner());

        // TODO for Smart Contracts we will have to rewind them too
        match transaction.get_data() {
            TransactionType::Transfer(txs) => {
                for output in txs {
                    keys.insert(&output.to);
                    if !assets.contains(&output.asset) {
                        assets.insert(&output.asset);
                    }
                }
            },
            TransactionType::Burn(asset, _) => {
                if !assets.contains(asset) {
                    assets.insert(asset);
                }
            },
            _ => {
                return Err(BlockchainError::SmartContractTodo)
            }
        }

        // keep the lowest nonce available
        let nonce = nonces.entry(transaction.get_owner()).or_insert(transaction.get_nonce());
        if *nonce < transaction.get_nonce() {
            *nonce = transaction.get_nonce();
        }
        Ok(())
    }
}

pub fn get_block_reward(supply: u64) -> u64 {
    let base_reward = (MAX_SUPPLY - supply) >> EMISSION_SPEED_FACTOR;
    base_reward
}