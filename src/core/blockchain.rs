use crate::config::{DEFAULT_P2P_BIND_ADDRESS, P2P_DEFAULT_MAX_PEERS, DEFAULT_DIR_PATH, DEFAULT_RPC_BIND_ADDRESS, DEFAULT_CACHE_SIZE, MAX_BLOCK_SIZE, EMISSION_SPEED_FACTOR, FEE_PER_KB, MAX_SUPPLY, DEV_FEE_PERCENT, GENESIS_BLOCK, DEV_ADDRESS, TIPS_LIMIT, TIMESTAMP_IN_FUTURE_LIMIT, STABLE_HEIGHT_LIMIT, GENESIS_BLOCK_HASH, MINIMUM_DIFFICULTY, GENESIS_BLOCK_DIFFICULTY, XELIS_ASSET, SIDE_BLOCK_REWARD_PERCENT};
use crate::core::immutable::Immutable;
use crate::crypto::address::Address;
use crate::crypto::hash::{Hash, Hashable};
use crate::globals::get_current_timestamp;
use crate::crypto::key::PublicKey;
use crate::p2p::server::P2pServer;
use crate::rpc::RpcServer;
use crate::rpc::websocket::NotifyEvent;
use super::difficulty::{check_difficulty, calculate_difficulty};
use super::block::{Block, CompleteBlock};
use super::mempool::Mempool;
use super::{transaction::*, blockdag};
use super::serializer::Serializer;
use super::error::BlockchainError;
use super::storage::Storage;
use std::sync::atomic::{Ordering, AtomicU64};
use std::collections::{HashMap, HashSet, VecDeque};
use async_recursion::async_recursion;
use tokio::sync::{Mutex, RwLock};
use log::{info, error, debug, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use rand::Rng;

#[derive(Debug, clap::StructOpt)]
pub struct Config {
    /// Optional node tag
    #[clap(short, long)]
    tag: Option<String>,
    /// P2p bind address to listen for incoming connections
    #[clap(short, long, default_value_t = String::from(DEFAULT_P2P_BIND_ADDRESS))]
    p2p_bind_address: String,
    /// Number of maximums peers allowed
    #[clap(short, long, default_value_t = P2P_DEFAULT_MAX_PEERS)]
    max_peers: usize,
    /// Rpc bind address to listen for HTTP requests
    #[clap(short, long, default_value_t = String::from(DEFAULT_RPC_BIND_ADDRESS))]
    rpc_bind_address: String,
    /// Add a priority node to connect when P2p is started
    #[clap(short = 'o', long)]
    priority_nodes: Vec<String>,
    /// Set dir path for blockchain storage
    #[clap(short = 's', long, default_value_t = String::from(DEFAULT_DIR_PATH))]
    dir_path: String,
    /// Set LRUCache size (0 = disabled)
    #[clap(short, long, default_value_t = DEFAULT_CACHE_SIZE)]
    cache_size: usize,
}

pub struct Blockchain {
    height: AtomicU64, // current block height
    topoheight: AtomicU64, // current topo height
    supply: AtomicU64, // current circulating supply based on coins already emitted
    burned: AtomicU64, // total burned coins
    mempool: RwLock<Mempool>, // mempool to retrieve/add all txs
    storage: RwLock<Storage>, // storage to retrieve/add blocks
    p2p: Mutex<Option<Arc<P2pServer>>>, // P2p module
    rpc: Mutex<Option<Arc<RpcServer>>>, // Rpc module
    dev_address: PublicKey // Dev address for block fee
}

impl Blockchain {
    pub async fn new(config: Config) -> Result<Arc<Self>, BlockchainError> {
        let dev_address = Address::from_string(&DEV_ADDRESS.to_owned())?;
        let use_cache = if config.cache_size > 0 {
            Some(config.cache_size)
        } else {
            None
        };

        let storage = Storage::new(config.dir_path, use_cache)?;
        let on_disk = storage.has_blocks();
        let (height, topoheight, supply, burned) = if on_disk {
            info!("Reading last metadata available...");
            let (topoheight, _, metadata) = storage.get_top_metadata().await?;
            let height = storage.get_top_height()?;
            (height, topoheight, metadata.get_supply(), metadata.get_burned_supply())
        } else { (0, 0, 0, 0) };

        info!("Initializing chain...");
        let blockchain = Self {
            height: AtomicU64::new(height),
            topoheight: AtomicU64::new(topoheight),
            supply: AtomicU64::new(supply),
            burned: AtomicU64::new(burned),
            mempool: RwLock::new(Mempool::new()),
            storage: RwLock::new(storage),
            p2p: Mutex::new(None),
            rpc: Mutex::new(None),
            dev_address: dev_address.to_public_key()
        };

        // include genesis block
        if !on_disk {
            blockchain.create_genesis_block().await?;
        }

        let arc = Arc::new(blockchain);
        // create P2P Server
        {
            let p2p = P2pServer::new(config.tag, config.max_peers, config.p2p_bind_address, Arc::clone(&arc))?;
            for addr in config.priority_nodes {
                let addr: SocketAddr = match addr.parse() {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("Error while parsing priority node: {}", e);
                        continue;
                    }
                };
                p2p.try_to_connect_to_peer(addr, true);
            }
            *arc.p2p.lock().await = Some(p2p);
        }

        // create RPC Server
        {
            let server = RpcServer::new(config.rpc_bind_address, Arc::clone(&arc)).await?;
            *arc.rpc.lock().await = Some(server);
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
            let genesis = CompleteBlock::from_hex(GENESIS_BLOCK.to_owned())?;
            if *genesis.get_miner() != self.dev_address {
                return Err(BlockchainError::GenesisBlockMiner)
            }

            if Hash::from_hex(GENESIS_BLOCK_HASH.to_owned())? != genesis.hash() {
                return Err(BlockchainError::InvalidGenesisHash)
            }

            debug!("Adding genesis block '{}' to chain", GENESIS_BLOCK_HASH);
            genesis
        } else {
            error!("No genesis block found!");
            info!("Generating a new genesis block...");
            let block = Block::new(0, get_current_timestamp(), Vec::new(), [0u8; 32], self.get_dev_address().clone(), Vec::new());
            let complete_block = CompleteBlock::new(Immutable::Owned(block), Vec::new());
            info!("Genesis generated: {}", complete_block.to_hex());
            complete_block
        };

        // hardcode genesis block topoheight
        storage.set_topo_height_for_block(&genesis_block.hash(), 0).await?;
        storage.set_top_height(0)?;

        self.add_new_block_for_storage(&mut storage, genesis_block, false).await?;

        Ok(())
    }

    // mine a block for current difficulty
    pub async fn mine_block(self: &Arc<Self>, key: &PublicKey) -> Result<(), BlockchainError> {
        let (mut block, difficulty) = {
            let storage = self.storage.read().await;
            let block = self.get_block_template_for_storage(&storage, key.clone()).await?;
            let difficulty = self.get_difficulty_at_tips(&storage, &block.get_tips()).await?;
            (block, difficulty)
        };
        let mut hash = block.hash();
        let mut current_height = self.get_height();
        while !check_difficulty(&hash, difficulty)? {
            if self.get_height() != current_height {
                current_height = self.get_height();
                block = self.get_block_template(key.clone()).await?;
            }
            block.nonce += 1;
            block.timestamp = get_current_timestamp();
            hash = block.hash();
        }

        let complete_block = self.build_complete_block_from_block(block).await?;
        let zelf = Arc::clone(self);
        let block_height = complete_block.get_height();
        zelf.add_new_block(complete_block, true).await?;
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

    pub async fn get_stable_height(&self) -> Result<u64, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_stable_height_for_storage(&storage).await
    }

    pub async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_top_block_hash_for_storage(&storage).await
    }
    
    pub async fn get_top_block_hash_for_storage(&self, storage: &Storage) -> Result<Hash, BlockchainError> {
        storage.get_hash_at_topo_height(self.get_topo_height()).await
    }

    pub async fn is_block_sync(&self, storage: &Storage, hash: &Hash) -> Result<bool, BlockchainError> {
        let current_height = self.get_height();
        self.is_block_sync_at_height(storage, hash, current_height).await
    }

    async fn is_block_sync_at_height(&self, storage: &Storage, hash: &Hash, height: u64) -> Result<bool, BlockchainError> {
        let block_height = storage.get_height_for_block(hash).await?;
        if block_height == 0 { // genesis block is a sync block
            return Ok(true)
        }

        if block_height + STABLE_HEIGHT_LIMIT > height || !storage.is_block_topological_ordered(hash).await {
            return Ok(false)
        }

        let tips_at_height = storage.get_blocks_at_height(block_height).await?;
        if tips_at_height.len() == 1 {
            return Ok(true)
        }

        if tips_at_height.len() > 1 {
            let mut blocks_in_main_chain = 0;
            for hash in tips_at_height {
                if storage.is_block_topological_ordered(&hash).await {
                    blocks_in_main_chain += 1;
                    if blocks_in_main_chain > 1 {
                        return Ok(false)
                    }
                }
            }

            let mut i = block_height - 1;
            let mut pre_blocks = HashSet::new();
            while i >= (block_height - STABLE_HEIGHT_LIMIT) && i != 0 {
                let blocks = storage.get_blocks_at_height(i).await?;
                pre_blocks.extend(blocks);
                i -= 1;
            }

            let sync_block_cumulative_difficulty = storage.get_cumulative_difficulty_for_block(hash).await?;

            for hash in pre_blocks {
                let cumulative_difficulty = storage.get_cumulative_difficulty_for_block(&hash).await?;
                if cumulative_difficulty >= sync_block_cumulative_difficulty {
                    return Ok(false)
                }
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
                let block_height = storage.get_height_for_block(hash).await?;
                return Ok((hash.clone(), block_height))
            }
            bases.push(self.find_tip_base(storage, hash, height).await?);
        }

        // sort ascending by height
        bases.sort_by(|(_, a), (_, b)| a.cmp(b));

        VecDeque::from(bases).pop_front().ok_or_else(|| BlockchainError::ExpectedTips)
    }

    async fn find_common_base(&self, storage: &Storage, tips: &HashSet<Hash>) -> Result<(Hash, u64), BlockchainError> {
        let mut best_height = 0;
        for hash in tips {
            let height = storage.get_height_for_block(hash).await?;
            if height > best_height {
                best_height = height;
            }
        }

        let mut bases = Vec::with_capacity(tips.len());
        for hash in tips {
            bases.push(self.find_tip_base(storage, hash, best_height).await?);
        }

        bases.sort_by(|(_, a), (_, b)| a.cmp(b));

        let (common_hash, _) = VecDeque::from(bases).pop_front().ok_or_else(|| BlockchainError::ExpectedTips)?;
        let common_height = storage.get_height_for_block(&common_hash).await?;
        Ok((common_hash, common_height))
    }

    async fn get_stable_height_for_storage(&self, storage: &Storage) -> Result<u64, BlockchainError> {
        let tips = storage.get_tips().await?;
        let (_, height) = self.find_common_base(storage, &tips).await?;
        Ok(height)
    }

    #[async_recursion] // TODO no recursion
    async fn build_reachability_recursive(&self, storage: &Storage, set: &mut HashSet<Hash>, hash: Hash, level: u8) -> Result<(), BlockchainError> {
        let tips = storage.get_past_blocks_of(&hash).await?;
        set.insert(hash);

        if level < STABLE_HEIGHT_LIMIT as u8 * 2 {
            for hash in tips.iter() {
                if !set.contains(hash) {
                    self.build_reachability_recursive(storage, set, hash.clone(), level + 1).await?;
                }
            }
        }

        Ok(())
    }

    async fn verify_non_reachability(&self, storage: &Storage, block: &Block) -> Result<bool, BlockchainError> {
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
                if i == j { // avoid self test
                    continue;
                }

                if reach[j].contains(&tips[i]) {
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
                set.insert(storage.get_topo_height_for_hash(hash).await?);
            } else {
                self.calculate_distance_from_mainchain_recursive(storage, set, hash).await?;
            }
        }
        Ok(())
    }

    async fn calculate_distance_from_mainchain(&self, storage: &Storage, hash: &Hash) -> Result<u64, BlockchainError> {
        if storage.is_block_topological_ordered(hash).await {
            return Ok(storage.get_topo_height_for_hash(hash).await?)
        }

        let mut set = HashSet::new(); // replace by a Vec and sort + remove first ?
        self.calculate_distance_from_mainchain_recursive(storage, &mut set, hash).await?;

        let mut lowest_height = u64::max_value();
        for height in set {
            if lowest_height > height {
                lowest_height = height;
            }
        }

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

        map.insert(hash.clone(), storage.get_difficulty_for_block(hash).await?);

        Ok(())
    }

    // TODO cache
    // find the sum of work done
    async fn find_tip_work_score(&self, storage: &Storage, hash: &Hash, base: &Hash, base_height: u64) -> Result<(HashMap<Hash, u64>, u64), BlockchainError> {
        let block = storage.get_block_by_hash(hash).await?;
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
        map.insert(hash.clone(), storage.get_difficulty_for_block(hash).await?);

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

    // TODO implement cache
    #[async_recursion]
    async fn generate_full_order(&self, storage: &Storage, hash: &Hash, base: &Hash, base_height: u64) -> Result<Vec<Hash>, BlockchainError> {
        let block = storage.get_block_by_hash(hash).await?;

        if block.get_tips().len() == 0 {
            return Ok(vec![Hash::from_hex(GENESIS_BLOCK_HASH.to_owned())?])
        }

        if hash == base {
            return Ok(vec![base.clone()])
        }

        let mut order: Vec<Hash> = Vec::new();
        let mut scores = Vec::new();
        for hash in block.get_tips() {
            let is_ordered = storage.is_block_topological_ordered(hash).await;
            if !is_ordered {
                let diff = storage.get_cumulative_difficulty_for_block(hash).await?;
                scores.push((hash, diff));
            } else if is_ordered && storage.get_topo_height_for_hash(hash).await? >= storage.get_topo_height_for_hash(base).await? {
                let diff = storage.get_cumulative_difficulty_for_block(hash).await?;
                scores.push((hash, diff))
            }
        }

        blockdag::sort_descending_by_cumulative_difficulty(&mut scores);

        for (hash, _) in scores {
            let sub_order = self.generate_full_order(storage, hash, base, base_height).await?;
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
        let best_block = storage.get_block_metadata_by_hash(best_tip).await?;
        let block = storage.get_block_metadata_by_hash(tip).await?;

        Ok(best_block.get_difficulty() * 91 / 100 < block.get_difficulty())
    }

    pub async fn get_difficulty_at_tips(&self, storage: &Storage, tips: &Vec<Hash>) -> Result<u64, BlockchainError> {
        if tips.len() == 0 { // Genesis difficulty
            return Ok(GENESIS_BLOCK_DIFFICULTY)
        }

        let height = blockdag::calculate_height_at_tips(storage, tips).await?;
        if height < 3 {
            return Ok(MINIMUM_DIFFICULTY)
        }

        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, tips).await?;
        let biggest_difficulty = storage.get_difficulty_for_block(best_tip).await?;
        let best_tip_timestamp = storage.get_timestamp_for_block(best_tip).await?;

        let parent_tips = storage.get_past_blocks_of(best_tip).await?;
        let parent_best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, &parent_tips).await?;
        let parent_best_tip_timestamp = storage.get_block_by_hash(parent_best_tip).await?.get_timestamp();
 
        let difficulty = calculate_difficulty(parent_best_tip_timestamp, best_tip_timestamp, biggest_difficulty);
        Ok(difficulty)
    }

    // pass in params the already computed block hash and its tips
    // check the difficulty calculated at tips
    // if the difficulty is valid, returns it (prevent to re-compute it)
    async fn verify_proof_of_work(&self, storage: &Storage, hash: &Hash, tips: &Vec<Hash>) -> Result<u64, BlockchainError> {
        let difficulty = self.get_difficulty_at_tips(storage, tips).await?;
        if check_difficulty(hash, difficulty)? {
            Ok(difficulty)
        } else {
            Err(BlockchainError::InvalidDifficulty)
        }
    }

    pub fn get_p2p(&self) -> &Mutex<Option<Arc<P2pServer>>> {
        &self.p2p
    }

    pub fn get_supply(&self) -> u64 {
        self.supply.load(Ordering::Acquire)
    }

    pub fn get_burned_supply(&self) -> u64 {
        self.burned.load(Ordering::Acquire)
    }

    pub fn get_dev_address(&self) -> &PublicKey {
        &self.dev_address
    }

    pub fn get_storage(&self) -> &RwLock<Storage> {
        &self.storage
    }

    pub fn get_mempool(&self) -> &RwLock<Mempool> {
        &self.mempool
    }

    pub async fn add_tx_to_mempool(&self, tx: Transaction, broadcast: bool) -> Result<(), BlockchainError> {
        let hash = tx.hash();
        let mut mempool = self.mempool.write().await;
        self.add_tx_for_mempool(&mut mempool, tx, hash, broadcast).await
    }

    async fn add_tx_for_mempool(&self, mempool: &mut Mempool, tx: Transaction, hash: Hash, broadcast: bool) -> Result<(), BlockchainError> {
        if mempool.contains_tx(&hash) {
            return Err(BlockchainError::TxAlreadyInMempool(hash))
        }

        {
            // get the highest nonce for this owner
            let owner = tx.get_owner();
            let mut nonces = HashMap::new();
            for (_, tx) in mempool.get_txs() {
                if tx.get_owner() == owner {
                    let nonce = nonces.entry(tx.get_owner()).or_insert(0);
                    // if the tx is in mempool, then the nonce should be valid.
                    if *nonce < tx.get_nonce() {
                        *nonce = tx.get_nonce();
                    }
                }
            }

            // if the nonce of tx is N + 1, we increment it to let it pass
            // so we have multiple TXs from same owner in the same block
            if let Some(nonce) = nonces.get_mut(owner) {
                if *nonce + 1 == tx.get_nonce() {
                    *nonce += 1;
                }
            }

            let storage = self.storage.read().await;
            self.verify_transaction_with_hash(&storage, &tx, &hash, Some(&mut nonces)).await?
        }

        if broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                p2p.broadcast_tx_hash(&hash).await;
            }
        }
        let tx = Arc::new(tx);
        mempool.add_tx(hash, tx.clone())?;

        // broadcast to websocket this tx
        if let Some(rpc) = self.rpc.lock().await.as_ref() {
            let rpc = rpc.clone();
            tokio::spawn(async move {
                if let Err(e) = rpc.notify_clients(NotifyEvent::TransactionAddedInMempool, tx).await {
                    debug!("Error while broadcasting event TransactionAddedInMempool to websocket: {}", e);
                }
            });
        }

        Ok(())
    }

    pub async fn get_block_template(&self, address: PublicKey) -> Result<Block, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_block_template_for_storage(&storage, address).await
    }

    pub async fn get_block_template_for_storage(&self, storage: &Storage, address: PublicKey) -> Result<Block, BlockchainError> {
        let extra_nonce: [u8; 32] = rand::thread_rng().gen::<[u8; 32]>(); // generate random bytes
        let tips_set = storage.get_tips().await?;
        let mut tips = Vec::with_capacity(tips_set.len());
        for hash in tips_set {
            tips.push(hash);
        }

        let mut sorted_tips = blockdag::sort_tips(&storage, &tips).await?;
        sorted_tips.truncate(3); // keep only first 3 heavier tips
        let height = blockdag::calculate_height_at_tips(storage, &tips).await?;
        let mut block = Block::new(height, get_current_timestamp(), sorted_tips, extra_nonce, address, Vec::new());

        let mempool = self.mempool.read().await;
        let txs = mempool.get_sorted_txs();
        let mut tx_size = 0;
        for tx in txs {
            if block.size() + tx_size + tx.get_size() > MAX_BLOCK_SIZE {
                break;
            }

            let transaction = mempool.view_tx(tx.get_hash())?;
            let nonce = storage.get_nonce(transaction.get_owner()).await?;
            if nonce < transaction.get_nonce() {
                debug!("Skipping {} with {} fees because another TX should be selected first due to nonce", tx.get_hash(), tx.get_fee());
            } else {
                // TODO no clone
                block.txs_hashes.push(tx.get_hash().clone());
                tx_size += tx.get_size();
            }
        }
        Ok(block)
    }

    pub async fn build_complete_block_from_block(&self, block: Block) -> Result<CompleteBlock, BlockchainError> {
        let mut transactions: Vec<Immutable<Transaction>> = Vec::with_capacity(block.get_txs_count());
        let mempool = self.mempool.read().await;
        for hash in &block.txs_hashes {
            let tx = mempool.view_tx(hash)?; // at this point, we don't want to lose/remove any tx, we clone it only
            transactions.push(Immutable::Arc(tx));
        }
        let complete_block = CompleteBlock::new(Immutable::Owned(block), transactions);
        Ok(complete_block)
    }

    pub async fn add_new_block(&self, block: CompleteBlock, broadcast: bool) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.add_new_block_for_storage(&mut storage, block, broadcast).await
    }

    pub async fn add_new_block_for_storage(&self, storage: &mut Storage, block: CompleteBlock, broadcast: bool) -> Result<(), BlockchainError> {
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
            error!("Expected at least one previous block for this block");
            return Err(BlockchainError::ExpectedTips)
        }

        if tips_count > 0 {
            let block_height_by_tips = blockdag::calculate_height_at_tips(storage, block.get_tips()).await?;
            let stable_height = self.get_stable_height_for_storage(storage).await?;
            debug!("Height by tips: {}, stable height: {}", block_height_by_tips, stable_height);

            if block_height_by_tips < stable_height {
                error!("Invalid block height at tips, got {} but should be {}", block_height_by_tips, stable_height);
                return Err(BlockchainError::InvalidBlockHeight(stable_height, block_height_by_tips))
            }
        }

        if !self.verify_non_reachability(storage, &block).await? {
            error!("{} has an invalid reachability", block);
            return Err(BlockchainError::InvalidReachability)
        }

        for hash in block.get_tips() {
            let previous_block = storage.get_block_by_hash(hash).await?;
            if previous_block.get_timestamp() > block.get_timestamp() { // block timestamp can't be less than previous block.
                error!("Invalid block timestamp, parent is less than new block");
                return Err(BlockchainError::TimestampIsLessThanParent(block.get_timestamp()));
            }

            let distance = self.calculate_distance_from_mainchain(storage, hash).await?;
            if current_height - distance >= STABLE_HEIGHT_LIMIT {
                error!("{} have deviated too much, maximum allowed is {} but got {} (current height: {}, distance: {})", block, STABLE_HEIGHT_LIMIT, current_height - distance, current_height, distance);
                return Err(BlockchainError::BlockDeviation)
            }
        }

        if tips_count > 1 {
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(&storage, block.get_tips()).await?;
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
        let difficulty = self.verify_proof_of_work(&storage, &block_hash, block.get_tips()).await?;
        debug!("PoW is valid for difficulty {}", difficulty);

        let mut total_fees: u64 = 0;
        let mut total_tx_size: usize = 0;
        { // Transaction verification
            let hashes_len = block.get_txs_hashes().len();
            let txs_len = block.get_transactions().len();
            if  hashes_len != txs_len {
                error!("Block has an invalid block header, transaction count mismatch (expected {} got {})!", txs_len, hashes_len);
                return Err(BlockchainError::InvalidBlockTxs(hashes_len, txs_len));
            }

            let mut cache_account: HashMap<&PublicKey, u64> = HashMap::new();
            let mut cache_tx: HashMap<Hash, bool> = HashMap::new(); // avoid using a TX multiple times
            for (tx, hash) in block.get_transactions().iter().zip(block.get_txs_hashes()) {
                let tx_hash = tx.hash();
                if tx_hash != *hash {
                    error!("Invalid tx {} vs {} in block header", tx_hash, hash);
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                }

                // block can't contains the same tx and should have tx hash in block header
                if cache_tx.contains_key(&tx_hash) {
                    error!("Block cannot contains the same TX {}", tx_hash);
                    return Err(BlockchainError::TxAlreadyInBlock(tx_hash));
                }

                self.verify_transaction_with_hash(storage, tx, &tx_hash, Some(&mut cache_account)).await?;
                total_fees += tx.get_fee();
                cache_tx.insert(tx_hash, true);
                total_tx_size += tx.size();
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
        storage.add_new_block(block.clone(), &txs, difficulty, block_hash.clone(), self.get_supply(), self.get_burned_supply()).await?;

        // Compute cumulative difficulty for block
        let cumulative_difficulty = { // TODO Refactor: stop cloning hash
            let cumulative_difficulty: u64 = if tips_count == 0 {
                GENESIS_BLOCK_DIFFICULTY
            } else {
                let mut tips = HashSet::with_capacity(block.get_tips().len());
                for hash in block.get_tips() {
                    tips.insert(hash.clone());
                }
                let (base, base_height) = self.find_common_base(storage, &tips).await?;
                let (_, cumulative_difficulty) = self.find_tip_work_score(&storage, &block_hash, &base, base_height).await?;
                cumulative_difficulty
            };
            storage.set_cumulative_difficulty_for_block(&block_hash, cumulative_difficulty).await?;
            debug!("Cumulative difficulty for block {}: {}", block_hash, cumulative_difficulty);
            cumulative_difficulty
        };
        // Transaction execution
        let mut mempool = self.mempool.write().await;
        for hash in block.get_txs_hashes() { // remove all txs present in mempool
            match mempool.remove_tx(hash) {
                Ok(_) => {
                    debug!("Removing tx hash '{}' from mempool", hash);
                },
                Err(_) => {}
            };
        }

        // track all changes in nonces
        let mut nonces = HashMap::new();
        for tx in &txs { // execute all txs
            self.execute_transaction(storage, &tx, &mut nonces).await?;
        }

        let mut tips = storage.get_tips().await?;
        tips.insert(block_hash.clone());
        for hash in block.get_tips() {
            tips.remove(hash);
        }

        let (base_hash, base_height) = self.find_common_base(storage, &tips).await?;
        debug!("Base hash: {}, base height: {}", base_hash, base_height);

        let best_tip = self.find_best_tip(storage, &tips, &base_hash, base_height).await?;
        debug!("Best tip selected: {}", best_tip);

        let full_order = self.generate_full_order(storage, &best_tip, &base_hash, base_height).await?;
        debug!("Generated full order size: {}", full_order.len());

        let base_topo = if tips_count == 0 {
            0
        } else {
            storage.get_topo_height_for_hash(&base_hash).await?
        };

        let mut highest_topo = 0;
        {
            let mut i = 0;
            for hash in full_order {
                highest_topo = base_topo + i;
                debug!("Block {} is now at topoheight {}", hash, highest_topo);
                storage.set_topo_height_for_block(&hash, highest_topo).await?;
                let supply = if highest_topo == 0 {
                    0
                } else {
                    storage.get_supply_at_topo_height(highest_topo - 1).await?
                };

                let block_reward = if self.is_side_block(storage, &hash).await? {
                    debug!("Block {} at topoheight {} is a side block", hash, highest_topo);
                    let reward = get_block_reward(supply);
                    reward * SIDE_BLOCK_REWARD_PERCENT / 100
                } else {
                    get_block_reward(supply)
                };

                storage.set_block_reward(&hash, block_reward)?;
                i += 1;
            }
        }

        let best_height = storage.get_height_for_block(best_tip).await?;
        let mut new_tips = Vec::new();
        for hash in tips {
            let tip_base_distance = self.calculate_distance_from_mainchain(storage, &hash).await?;
            if best_height - tip_base_distance < STABLE_HEIGHT_LIMIT - 1 {
                debug!("Adding {} as new tips", hash);
                new_tips.push(hash);
            } else {
                warn!("Rusty TIP declared stale {} with best height: {}, deviation: {}, tip base distance: {}", hash, best_height, best_height - tip_base_distance, tip_base_distance);
                // TODO rewind stale TIP
            }
        }

        tips = HashSet::new();
        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(&storage, &new_tips).await?.clone();
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
        if current_height == 0 || highest_topo > self.get_topo_height() {
            storage.set_top_topoheight(highest_topo)?;
            self.topoheight.store(highest_topo, Ordering::Release);

            // when topo height extends to a new stable block, give miner rewards
            if highest_topo >= STABLE_HEIGHT_LIMIT {
                let last_stable_topo = highest_topo - STABLE_HEIGHT_LIMIT;
                let hash = storage.get_hash_at_topo_height(last_stable_topo).await?;
                let block_reward = storage.get_block_reward(&hash)?;
                let stable_block = storage.get_block_by_hash(&hash).await?;
                debug!("New highest topoheight detected: give {} rewards for miner of block {} at topoheight {}", block_reward, hash, last_stable_topo);
                self.reward_miner(storage, &stable_block, block_reward).await?;
            }
        }
        storage.store_tips(&tips)?;

        if current_height == 0 || block.get_height() > self.get_height() {
            storage.set_top_height(block.get_height())?;
            self.height.store(block.get_height(), Ordering::Release);
        }

        // TODO self.supply.fetch_add(block_reward, Ordering::Release);
        if storage.is_block_topological_ordered(&block_hash).await {
            let topoheight = storage.get_topo_height_for_hash(&block_hash).await?;
            debug!("Adding new '{}' {} at topoheight {}", block_hash, block, topoheight);
        } else {
            debug!("Adding new '{}' {} with no topoheight (not ordered)!", block_hash, block);
        }

        if broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                debug!("broadcast block to peers");
                p2p.broadcast_block(&block, cumulative_difficulty, highest_topo, self.get_height(), &block_hash).await;
            }
        }

        // broadcast to websocket new block
        if let Some(rpc) = self.rpc.lock().await.as_ref() {
            let rpc = rpc.clone();
            // don't block mutex/lock more than necessary, we move it in another task
            tokio::spawn(async move {
                if let Err(e) = rpc.notify_clients(NotifyEvent::NewBlock, block).await {
                    debug!("Error while broadcasting event NewBlock to websocket: {}", e);
                }
            });
        }

        // Clean all old txs
        mempool.clean_up(storage, nonces).await;

        Ok(())
    }

    // if a block is not ordered, it's an orphaned block and its transactions are not honoured
    pub async fn is_block_orphaned_for_storage(&self, storage: &Storage, hash: &Hash) -> bool {
        !storage.is_block_topological_ordered(hash).await
    }

    // a block is a side block if its ordered and its block height is less than or equal to height of past 8 topographical blocks
    pub async fn is_side_block(&self, storage: &Storage, hash: &Hash) -> Result<bool, BlockchainError> {
        if !storage.is_block_topological_ordered(hash).await {
            return Ok(false)
        }

        let topoheight = storage.get_topo_height_for_hash(hash).await?;
        if topoheight == 0 {
            return Ok(false)
        }

        let height = storage.get_height_for_block(hash).await?;

        let mut counter = 0;
        let mut i = topoheight - 1;
        while counter < STABLE_HEIGHT_LIMIT && i > 0 {
            let hash = storage.get_hash_at_topo_height(i).await?;
            let previous_height = storage.get_height_for_block(&hash).await?;
            
            if height <= previous_height {
                return Ok(true)
            }
            counter += 1;
            i -= 1;
        }

        Ok(false)
    }

    pub async fn rewind_chain(&self, count: usize) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.rewind_chain_for_storage(&mut storage, count).await
    }

    // TODO missing burned supply, txs etc
    pub async fn rewind_chain_for_storage(&self, storage: &mut Storage, count: usize) -> Result<(), BlockchainError> {
        let height = self.get_height();
        let topoheight = self.get_topo_height();
        warn!("Rewind chain with count = {}, height = {}, topoheight = {}", count, height, topoheight);
        let (height, topoheight, metadata, txs, miners) = storage.pop_blocks(height, topoheight, count as u64).await?;
        
        // rewind all txs
        {
            let mut changes = HashMap::new();
            let mut nonces = HashMap::new();
            for (hash, tx) in &txs {
                debug!("Rewinding tx hash: {}", hash);
                self.rewind_transaction(storage, tx, &mut changes, &mut nonces).await?;
            }

            // merge miners reward to TX changes
            for (key, reward) in &miners {
                let assets = changes.entry(&key).or_insert(HashMap::new());
                if let Some(balance) = assets.get_mut(&XELIS_ASSET) {
                    *balance -= reward;
                } else {
                    let balance = storage.get_balance_for(&key, &XELIS_ASSET).await?;
                    assets.insert(&XELIS_ASSET, balance - reward);
                }
            }

            // apply all changes to balance
            for (key, assets) in changes {
                for (asset, amount) in assets {
                    storage.set_balance_for(key, asset, amount)?;
                }
            }

            // apply all changes to nonce
            for (key, nonce) in nonces {
                storage.set_nonce(key, nonce).await?;
            }

            let mut mempool = self.mempool.write().await;
            for (hash, tx) in txs {
                if let Err(e) = self.add_tx_for_mempool(&mut mempool, tx.as_ref().clone(), hash, false).await {
                    debug!("TX rewinded is not compatible anymore: {}", e);
                }
            }
        }
        self.height.store(height, Ordering::Release);
        self.topoheight.store(topoheight, Ordering::Release);
        self.supply.store(metadata.get_supply(), Ordering::Release); // recaculate supply
        self.burned.store(metadata.get_burned_supply(), Ordering::Release);
        Ok(())
    }

    // verify the transaction and returns fees available
    // nonces allow us to support multiples tx from same owner in the same block
    // txs must be sorted in ascending order based on account nonce 
    async fn verify_transaction_with_hash<'a>(&self, storage: &Storage, tx: &'a Transaction, hash: &Hash, nonces: Option<&mut HashMap<&'a PublicKey, u64>>) -> Result<(), BlockchainError> {
        let mut total_deducted: HashMap<&'a Hash, u64> = HashMap::new();
        total_deducted.insert(&XELIS_ASSET, tx.get_fee());

        match tx.get_data() {
            TransactionType::Transfer(txs) => {
                if txs.len() == 0 { // don't accept any empty tx
                    return Err(BlockchainError::TxEmpty(hash.clone()))
                }

                for output in txs {
                    if output.to == *tx.get_owner() { // we can't transfer coins to ourself, why would you do that ?
                        return Err(BlockchainError::InvalidTransactionToSender(hash.clone()))
                    }

                    *total_deducted.entry(&output.asset).or_insert(0) += output.amount;
                }
            }
            TransactionType::Burn(asset, amount) => {
                *total_deducted.entry(asset).or_insert(0) += amount;
            },
            _ => {
                // TODO implement SC
                return Err(BlockchainError::SmartContractTodo)
            }
        };

        for (asset, amount) in total_deducted {
            let balance = storage.get_balance_for(tx.get_owner(), asset).await?;
            if balance < amount { // verify that the user have enough funds
                return Err(BlockchainError::NotEnoughFunds(tx.get_owner().clone(), asset.clone(), balance, amount))
            }
        }

        // nonces can be already pre-computed to support multi nonces at the same time in block/mempool
        if let Some(nonces) = nonces {
            let nonce = if !nonces.contains_key(tx.get_owner()) && storage.has_nonce(tx.get_owner()).await? {
                storage.get_nonce(tx.get_owner()).await?
            } else {
                0
            };

            let nonce = nonces.entry(tx.get_owner()).or_insert(nonce);
            if *nonce != tx.get_nonce() {
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

        Ok(())
    }

    async fn reward_miner(&self, storage: &mut Storage, block: &Block, mut block_reward: u64) -> Result<(), BlockchainError> {
        if DEV_FEE_PERCENT != 0 {
            let dev_fee = block_reward * DEV_FEE_PERCENT / 100;
            let mut balance = storage.get_balance_for(self.get_dev_address(), &XELIS_ASSET).await?;
            balance += dev_fee;
            storage.set_balance_for(self.get_dev_address(), &XELIS_ASSET, balance)?;
            block_reward -= dev_fee;
        }
        let mut balance = storage.get_balance_for(block.get_miner(), &XELIS_ASSET).await?;

        let mut total_fees = 0;
        for hash in block.get_txs_hashes() {
            let tx = storage.get_transaction(hash).await?;
            total_fees += tx.get_fee();
        }
        balance += block_reward + total_fees;
        storage.set_balance_for(block.get_miner(), &XELIS_ASSET, balance)?;

        Ok(())
    }

    async fn execute_transaction<'a>(&self, storage: &mut Storage, transaction: &'a Transaction, nonces: &mut HashMap<&'a PublicKey, u64>) -> Result<(), BlockchainError> {
        let mut total_deducted: HashMap<&'a Hash, u64> = HashMap::new();
        total_deducted.insert(&XELIS_ASSET, transaction.get_fee());

        match transaction.get_data() {
            TransactionType::Burn(asset, amount) => {
                *total_deducted.entry(asset).or_insert(0) += amount;

                // record the amount burned
                if *asset == XELIS_ASSET {
                    self.burned.fetch_add(*amount, Ordering::Release);
                }
            }
            TransactionType::Transfer(txs) => {
                for output in txs {
                    // update receiver's account
                    let balance = storage.get_balance_for(&output.to, &output.asset).await?;
                    storage.set_balance_for(&output.to, &output.asset, balance + output.amount)?;

                    *total_deducted.entry(&output.asset).or_insert(0) += output.amount;
                }
            }
            _ => {
                return Err(BlockchainError::SmartContractTodo)
            }
        };

        for (asset, amount) in total_deducted {
            let balance = storage.get_balance_for(transaction.get_owner(), asset).await?;
            storage.set_balance_for(&transaction.get_owner(), asset, balance - amount)?;
        }

        // no need to read from disk, transaction nonce has been verified already
        let nonce = transaction.get_nonce() + 1;
        storage.set_nonce(transaction.get_owner(), nonce).await?;
        nonces.insert(transaction.get_owner(), nonce);

        Ok(())
    }

    async fn rewind_transaction<'a>(&self, storage: &mut Storage, transaction: &'a Transaction, changes: &mut HashMap<&'a PublicKey, HashMap<&'a Hash, u64>>, nonces: &mut HashMap<&'a PublicKey, u64>) -> Result<(), BlockchainError> {
        // give fees back
        let sender: &mut HashMap<&'a Hash, u64> = changes.entry(transaction.get_owner()).or_insert(HashMap::new());
        {
            if let Some(balance) = sender.get_mut(&XELIS_ASSET) {
                *balance += transaction.get_fee();
            }  else {
                let balance = storage.get_balance_for(transaction.get_owner(), &XELIS_ASSET).await?;
                sender.insert(&XELIS_ASSET, balance + transaction.get_fee());
            }
        }

        match transaction.get_data() {
            TransactionType::Burn(asset, amount) => {
                if let Some(balance) = sender.get_mut(&asset) {
                    *balance += amount;
                }  else {
                    let balance = storage.get_balance_for(transaction.get_owner(), asset).await?;
                    sender.insert(asset, balance + amount);
                }
            }
            TransactionType::Transfer(txs) => {
                for output in txs {
                    // update receiver's account
                    let receiver = changes.entry(&output.to).or_insert(HashMap::new());
                    if let Some(balance) = receiver.get_mut(&output.asset) {
                        *balance -= output.amount;
                    } else {
                        let balance = storage.get_balance_for(&output.to, &output.asset).await?;
                        receiver.insert(&output.asset, balance - output.amount);
                    }

                    // update sender balance too
                    let sender = changes.entry(transaction.get_owner()).or_insert(HashMap::new());
                    if let Some(balance) = sender.get_mut(&output.asset) {
                        *balance += output.amount;
                    } else {
                        let balance = storage.get_balance_for(&output.to, &output.asset).await?;
                        sender.insert(&output.asset, balance + output.amount);
                    }
                }
            }
            _ => {
                // TODO
            }
        };

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

pub fn calculate_tx_fee(tx_size: usize) -> u64 {
    let mut size_in_kb = tx_size as u64 / 1024;

    if tx_size % 1024 != 0 { // we consume a full kb for fee
        size_in_kb += 1;
    }
    
    size_in_kb * FEE_PER_KB
}

use std::fmt::{Display, Error, Formatter};

impl Display for Blockchain {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "Blockchain[height: {}, accounts: {}, supply: {}]", self.get_height(), 0, self.get_supply())
    }
}