use crate::config::{DEFAULT_P2P_BIND_ADDRESS, P2P_DEFAULT_MAX_PEERS, DEFAULT_DIR_PATH, DEFAULT_RPC_BIND_ADDRESS, MAX_BLOCK_SIZE, EMISSION_SPEED_FACTOR, FEE_PER_KB, MAX_SUPPLY, REGISTRATION_DIFFICULTY, DEV_FEE_PERCENT, GENESIS_BLOCK, DEV_ADDRESS, TIPS_LIMIT, TIMESTAMP_IN_FUTURE_LIMIT, STABLE_HEIGHT_LIMIT};
use crate::core::immutable::Immutable;
use crate::crypto::address::Address;
use crate::crypto::hash::{Hash, Hashable};
use crate::globals::get_current_timestamp;
use crate::crypto::key::PublicKey;
use crate::p2p::server::P2pServer;
use crate::rpc::RpcServer;
use super::difficulty::{check_difficulty, calculate_difficulty};
use super::block::{Block, CompleteBlock};
use super::mempool::{Mempool, SortedTx};
use super::reader::{ReaderError, Reader};
use super::{transaction::*, blockdag};
use super::serializer::Serializer;
use super::error::BlockchainError;
use super::storage::Storage;
use super::writer::Writer;
use std::sync::atomic::{Ordering, AtomicU64};
use std::collections::{HashMap, HashSet, VecDeque};
use async_recursion::async_recursion;
use num_bigint::ToBigUint;
use tokio::sync::{Mutex, RwLock};
use log::{info, error, debug};
use std::net::SocketAddr;
use std::sync::Arc;
use rand::Rng;

#[derive(serde::Serialize)]
pub struct Account {
    balance: AtomicU64,
    nonce: AtomicU64
}

impl Account {
    pub fn new(balance: u64, nonce: u64) -> Self {
        Self {
            balance: AtomicU64::new(balance),
            nonce: AtomicU64::new(nonce)
        }
    }

    pub fn get_balance(&self) -> &AtomicU64 {
        &self.balance
    }

    pub fn get_nonce(&self) -> &AtomicU64 {
        &self.nonce
    }

    pub fn read_balance(&self) -> u64 {
        self.balance.load(Ordering::Acquire)
    }

    pub fn read_nonce(&self) -> u64 {
        self.nonce.load(Ordering::Acquire)
    }
}

impl Serializer for Account {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let balance = reader.read_u64()?;
        let nonce = reader.read_u64()?;
        Ok(Self::new(balance, nonce))
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.read_balance());
        writer.write_u64(&self.read_nonce());
    }
}

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
    #[clap(short = 'n', long)]
    priority_nodes: Vec<String>,
    /// Set dir path for blockchain storage
    #[clap(short = 's', long, default_value_t = String::from(DEFAULT_DIR_PATH))]
    dir_path: String
}

pub struct Blockchain {
    height: AtomicU64, // current block height 
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
        let storage = Storage::new(config.dir_path)?;
        let on_disk = storage.has_blocks();
        let (height, supply, burned) = if on_disk {
            info!("Reading last metadata available...");
            let (height, metadata) = storage.get_top_metadata()?;
            (height, metadata.get_supply(), metadata.get_burned_supply())
        } else { (0, 0, 0) };

        let blockchain = Self {
            height: AtomicU64::new(height),
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
        storage.register_account(self.dev_address.clone()).await?;

        if GENESIS_BLOCK.len() != 0 {
            info!("De-serializing genesis block...");
            let genesis = CompleteBlock::from_hex(GENESIS_BLOCK.to_owned())?;
            if *genesis.get_miner() != self.dev_address {
                return Err(BlockchainError::GenesisBlockMiner)
            }
            debug!("Adding genesis block to chain");
            self.add_new_block_for_storage(&mut storage, genesis, false).await?;
        } else {
            error!("No genesis block found!");
            info!("Generating a new genesis block...");
            let miner_tx = Transaction::new(self.get_dev_address().clone(), TransactionVariant::Coinbase);
            let block = Block::new(0, get_current_timestamp(), Vec::new(), [0u8; 32], Immutable::Owned(miner_tx), Vec::new());
            let complete_block = CompleteBlock::new(Immutable::Owned(block), 1, Vec::new());
            info!("Genesis generated & added: {}, hash: {}", complete_block.to_hex(), complete_block.hash());
            self.add_new_block_for_storage(&mut storage, complete_block, false).await?;
        }

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

    async fn is_block_sync_at_height(&self, storage: &Storage, hash: &Hash, height: u64) -> Result<bool, BlockchainError> {
        let block_height = storage.get_height_for_block(hash).await?;
        if block_height == 0 {
            return Ok(true)
        }

        if block_height + STABLE_HEIGHT_LIMIT > height || !self.is_block_ordered(storage, hash).await? {
            return Ok(false)
        }

        let tips_at_height = storage.get_tips_at_height(block_height).await?;
        let mut blocks_in_main_chain = 0;
        for hash in tips_at_height {
            if self.is_block_ordered(storage, &hash).await? {
                blocks_in_main_chain += 1;
                if blocks_in_main_chain > 1 {
                    return Ok(false)
                }
            }
        }

        let mut i = block_height - 1;
        let mut pre_blocks = HashSet::new();
        while i >= (block_height - STABLE_HEIGHT_LIMIT) && i != 0 {
            let blocks = storage.get_tips_at_height(i).await?;
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

        Ok(true)
    }

    // TODO: cache based on height/hash
    #[async_recursion]
    async fn find_tip_base(&self, storage: &Storage, hash: &Hash, height: u64) -> Result<(Hash, u64), BlockchainError> {
        let tips = storage.get_tips_of(hash).await?;
        let tips_count = tips.len();
        if tips_count == 0 { // TODO genesis hash from config
            let (hash, _) = storage.get_block_at_height(0).await?;
            return Ok((hash, 0))
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
        let tips = storage.get_tips_of(&hash).await?;
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

                if reach[j].contains(&tips[j]) {
                    return Ok(false)
                }
            }
        }
        Ok(true)
    }

    async fn is_block_ordered(&self, storage: &Storage, hash: &Hash) -> Result<bool, BlockchainError> {
        let topo_height = storage.get_topo_height_for_block(hash).await?;
        let hash_at_topo = storage.get_block_hash_at_topo_height(topo_height).await?;
        Ok(*hash == hash_at_topo)
    }

    #[async_recursion] // TODO no recursion
    async fn calculate_distance_from_mainchain_recursive(&self, storage: &Storage, set: &mut HashSet<u64>, hash: &Hash) -> Result<(), BlockchainError> {
        let tips = storage.get_tips_of(hash).await?;
        for hash in tips.iter() {
            if self.is_block_ordered(storage, &hash).await? {
                set.insert(storage.get_topo_height_for_block(hash).await?);
            } else {
                self.calculate_distance_from_mainchain_recursive(storage, set, hash).await?;
            }
        }
        Ok(())
    }

    async fn calculate_distance_from_mainchain(&self, storage: &Storage, hash: &Hash) -> Result<u64, BlockchainError> {
        if self.is_block_ordered(storage, hash).await? {
            return Ok(storage.get_topo_height_for_block(hash).await?)
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

    async fn find_best_tip<'a>(&self, storage: &Storage, tips: &'a HashSet<Hash>, base: &Hash, base_height: u64) -> Result<&'a Hash, BlockchainError> {
        if tips.len() == 0 {
            return Err(BlockchainError::ExpectedTips)
        }

        let mut scores = Vec::with_capacity(tips.len());
        for hash in tips {
            let (_, cumulative_difficulty) = (0, 0); // TODO self.find_tip_work_score(storage, hash, base, base_height).await?;
            scores.push((hash, cumulative_difficulty));
        }

        blockdag::sort_descending_by_cumulative_difficulty(&mut scores);
        let (best_tip, _) = scores[0];
        Ok(best_tip)
    }

    // TODO implement cache
    async fn generate_full_order(&self, storage: &Storage, hash: &Hash, base: &Hash, base_height: u64) -> Result<Vec<Hash>, BlockchainError> {
        let block = storage.get_block_by_hash(hash).await?;

        let mut order: Vec<Hash> = Vec::new();
        if block.get_tips().len() == 0 {
            todo!("return the Genesis block hash")
        }

        if hash == base {
            order.push(base.clone());
            return Ok(order)
        }

        todo!("")
    }

    async fn validate_tips(&self, storage: &Storage, best_tip: &Hash, tip: &Hash) -> Result<bool, BlockchainError> {
        let best_block = storage.get_block_metadata_by_hash(best_tip).await?;
        let block = storage.get_block_metadata_by_hash(tip).await?;

        Ok(best_block.get_difficulty() * 91 / 100 < block.get_difficulty())
    }

    pub async fn get_difficulty_at_tips(&self, storage: &Storage, tips: &Vec<Hash>) -> Result<u64, BlockchainError> {
        if tips.len() == 0 { // Genesis difficulty
            return Ok(1)
        }

        let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, tips).await?;
        let biggest_difficulty = storage.get_difficulty_for_block(best_tip).await?;
        let best_tip_timestamp = storage.get_timestamp_for_block(best_tip).await?;

        let parent_tips = storage.get_tips_of(best_tip).await?;
        let parent_best_tip = blockdag::find_best_tip_by_cumulative_difficulty(storage, &parent_tips).await?;
        let parent_best_tip_timestamp = storage.get_block_by_hash(parent_best_tip).await?.get_timestamp();
 
        let difficulty = calculate_difficulty(parent_best_tip_timestamp, best_tip_timestamp, biggest_difficulty);
        Ok(difficulty)
    }

    // pass in params the already computed block hash
    async fn verify_proof_of_work(&self, storage: &Storage, hash: &Hash, block: &Block) -> Result<bool, BlockchainError> {
        let difficulty = self.get_difficulty_at_tips(storage, block.get_tips()).await?;
        Ok(check_difficulty(hash, difficulty)?)
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

    pub async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        Ok(self.storage.read().await.get_top_block_hash()?)
    }

    pub fn get_mempool(&self) -> &RwLock<Mempool> {
        &self.mempool
    }

    pub async fn add_tx_to_mempool(&self, tx: Transaction, broadcast: bool) -> Result<(), BlockchainError> {
        let hash = tx.hash();
        let mut mempool = self.mempool.write().await;
        if mempool.contains_tx(&hash) {
            return Err(BlockchainError::TxAlreadyInMempool(hash))
        }

        let fee = {
            let storage = self.storage.read().await;
            self.verify_transaction_with_hash(&storage, &tx, &hash, false).await?
        };
        if broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                p2p.broadcast_tx_hash(&hash).await;
            }
        }
        mempool.add_tx_with_fee(hash, Arc::new(tx), fee)
    }

    pub async fn get_block_template(&self, address: PublicKey) -> Result<Block, BlockchainError> {
        let storage = self.storage.read().await;
        self.get_block_template_for_storage(&storage, address).await
    }

    pub async fn get_block_template_for_storage(&self, storage: &Storage, address: PublicKey) -> Result<Block, BlockchainError> {
        let coinbase_tx = Transaction::new(address, TransactionVariant::Coinbase);
        let extra_nonce: [u8; 32] = rand::thread_rng().gen::<[u8; 32]>(); // generate random bytes

        let tips_set = storage.get_tips().await?;
        let mut tips = Vec::with_capacity(tips_set.len());
        for hash in tips_set {
            tips.push(hash);
        }

        let mut sorted_tips = blockdag::sort_tips(&storage, &tips).await?;
        sorted_tips.truncate(3); // keep only first 3 tips
        let mut block = Block::new(self.get_height() + 1, get_current_timestamp(), sorted_tips, extra_nonce, Immutable::Owned(coinbase_tx), Vec::new());
        let mempool = self.mempool.read().await;
        let txs: &Vec<SortedTx> = mempool.get_sorted_txs();
        let mut tx_size = 0;
        for tx in txs {
            tx_size += tx.get_size();
            if block.size() + tx_size > MAX_BLOCK_SIZE {
                break;
            }
            block.txs_hashes.push(tx.get_hash().clone());
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
        let storage = self.storage.read().await;
        let difficulty = self.get_difficulty_at_tips(&storage, &block.get_tips()).await?;
        let complete_block = CompleteBlock::new(Immutable::Owned(block), difficulty, transactions);
        Ok(complete_block)
    }

    pub async fn check_validity(&self) -> Result<(), BlockchainError> {
        let storage = self.storage.read().await;
        let blocks_count = storage.count_blocks() as u64;
        if self.get_height() != blocks_count as u64 {
            return Err(BlockchainError::InvalidBlockHeight(self.get_height(), blocks_count as u64))
        }

        // TODO re calculate ALL accounts balances
        let mut circulating_supply = 0;
        for height in 0..=blocks_count {
            let metadata = storage.get_block_metadata(height).await?;
            let hash = metadata.get_hash();
            debug!("Checking height {} with hash {}", height, hash);
            let block = storage.get_block_by_hash(hash).await?;
            if block.get_height() != height as u64 {
                debug!("Invalid block height for block {}, got {} but expected {}", hash, block.get_height(), height);
                return Err(BlockchainError::InvalidBlockHeight(block.get_height(), height as u64))
            }

            let tips_count = block.get_tips().len();
            if tips_count > TIPS_LIMIT {
                return Err(BlockchainError::InvalidTips) // only 3 tips are allowed
            }
    
            if tips_count == 0 && height != 0 {
                return Err(BlockchainError::ExpectedTips)
            }

            if tips_count > 0 {
                let block_height_by_tips = blockdag::calculate_height_at_tips(&storage, block.get_tips()).await?;
                let stable_height = self.get_stable_height_for_storage(&storage).await?;
                if block_height_by_tips < stable_height {
                    return Err(BlockchainError::InvalidBlockHeight(stable_height, block_height_by_tips))
                }
            }

            if !self.verify_non_reachability(&storage, &block).await? {
                return Err(BlockchainError::InvalidReachability)
            }

            for hash in block.get_tips() {
                let previous_block = storage.get_block_by_hash(hash).await?;
                if previous_block.get_height() + 1 != block.get_height() {
                    return Err(BlockchainError::InvalidBlockHeight(previous_block.get_height() + 1, block.get_height()));
                }
    
                if previous_block.get_timestamp() > block.get_timestamp() {
                    return Err(BlockchainError::TimestampIsLessThanParent(block.get_timestamp()));
                }
    
                let distance = self.calculate_distance_from_mainchain(&storage, hash).await?;
                if height - distance >= STABLE_HEIGHT_LIMIT {
                    return Err(BlockchainError::BlockDeviation)
                }
            }

            let difficulty = self.get_difficulty_at_tips(&storage, block.get_tips()).await?;
            if metadata.get_difficulty() != difficulty {
                error!("Invalid stored difficulty for block {} at height {}, difficulty stored: {}, calculated: {} ", hash, height, metadata.get_difficulty(), difficulty);
                return Err(BlockchainError::InvalidDifficulty)
            }

            let txs_len = block.get_transactions().len();
            let txs_hashes_len = block.get_txs_hashes().len();
            if txs_len != txs_hashes_len {
                return Err(BlockchainError::InvalidBlockTxs(txs_hashes_len, txs_len));
            }

            if !self.verify_proof_of_work(&storage, hash, &block).await? {
                return Err(BlockchainError::InvalidDifficulty)
            }

            if !block.get_miner_tx().is_coinbase() || !block.get_miner_tx().verify_signature()? {
                return Err(BlockchainError::InvalidMinerTx)
            }

            let reward = get_block_reward(circulating_supply);
            let mut total_tx_size = 0;
            for tx_hash in block.get_transactions() {
                let tx = storage.get_transaction(tx_hash).await?;
                if !tx.is_coinbase() {
                    self.verify_transaction_with_hash(&storage, &tx, &tx_hash, true).await?; // TODO check when account have no more funds
                } else {
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash.clone()))
                }

                if !block.get_txs_hashes().contains(&tx_hash) { // check if tx is in txs hashes
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash.clone()))
                }

                total_tx_size += tx.size();
            }

            if total_tx_size + block.size() > MAX_BLOCK_SIZE {
                return Err(BlockchainError::InvalidBlockSize(MAX_BLOCK_SIZE, total_tx_size + block.size()))
            }

            circulating_supply += reward;
        }

        // TODO
        /*let mut total_supply_from_accounts = 0;
        for (_, account) in storage.get_accounts() {
            total_supply_from_accounts += account.balance;
        }*/

        if circulating_supply != self.get_supply() - self.get_burned_supply() {
            return Err(BlockchainError::InvalidCirculatingSupply(circulating_supply, self.get_supply()));
        }

        /*if total_supply_from_accounts != circulating_supply {
            return Err(BlockchainError::InvalidCirculatingSupply(total_supply_from_accounts, self.get_supply()));
        }*/

        Ok(())
    }

    pub async fn add_new_block(&self, block: CompleteBlock, broadcast: bool) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.add_new_block_for_storage(&mut storage, block, broadcast).await
    }

    pub async fn add_new_block_for_storage(&self, storage: &mut Storage, block: CompleteBlock, broadcast: bool) -> Result<(), BlockchainError> {
        let block_hash = block.hash();
        if storage.has_block(&block_hash).await? {
            return Err(BlockchainError::AlreadyInChain)
        }

        if block.get_timestamp() > get_current_timestamp() + TIMESTAMP_IN_FUTURE_LIMIT { // accept 2s in future
            return Err(BlockchainError::TimestampIsInFuture(get_current_timestamp(), block.get_timestamp()));
        }

        let tips_count = block.get_tips().len();
        if tips_count > TIPS_LIMIT {
            return Err(BlockchainError::InvalidTips) // only 3 tips are allowed
        }

        let current_height = self.get_height();
        if tips_count == 0 && current_height != 0 {
            return Err(BlockchainError::ExpectedTips)
        }

        if tips_count > 0 {
            let block_height_by_tips = blockdag::calculate_height_at_tips(storage, block.get_tips()).await?;
            let stable_height = self.get_stable_height_for_storage(storage).await?;

            if block_height_by_tips < stable_height {
                return Err(BlockchainError::InvalidBlockHeight(stable_height, block_height_by_tips))
            }
        }

        if !self.verify_non_reachability(storage, &block).await? {
            return Err(BlockchainError::InvalidReachability)
        }

        for hash in block.get_tips() {
            let previous_block = storage.get_block_by_hash(hash).await?;
            if previous_block.get_height() + 1 != block.get_height() {
                return Err(BlockchainError::InvalidBlockHeight(previous_block.get_height() + 1, block.get_height()));
            }

            if previous_block.get_timestamp() > block.get_timestamp() { // block timestamp can't be less than previous block.
                return Err(BlockchainError::TimestampIsLessThanParent(block.get_timestamp()));
            }

            let distance = self.calculate_distance_from_mainchain(storage, hash).await?;
            if current_height - distance >= STABLE_HEIGHT_LIMIT {
                return Err(BlockchainError::BlockDeviation)
            }
        }

        if tips_count > 1 {
            let best_tip = blockdag::find_best_tip_by_cumulative_difficulty(&storage, block.get_tips()).await?;
            for hash in block.get_tips() {
                if best_tip != hash {
                    if !self.validate_tips(storage, best_tip, hash).await? {
                        return Err(BlockchainError::InvalidTips)
                    }
                }
            }
        }

        if !self.verify_proof_of_work(&storage, &block_hash, &block).await? {
            return Err(BlockchainError::InvalidDifficulty)
        }

        let mut total_fees: u64 = 0;
        let mut total_tx_size: usize = 0;
        { // Transaction verification
            let hashes_len = block.get_txs_hashes().len();
            let txs_len = block.get_transactions().len();
            if  hashes_len != txs_len {
                return Err(BlockchainError::InvalidBlockTxs(hashes_len, txs_len));
            }
            let mut cache_tx: HashMap<Hash, bool> = HashMap::new(); // avoid using a TX multiple times
            let mut registrations: HashMap<&PublicKey, bool> = HashMap::new(); // avoid multiple registration of the same public key 
            for tx in block.get_transactions() {
                let tx_hash = tx.hash();
                // block can't contains the same tx and should have tx hash in block header
                if cache_tx.contains_key(&tx_hash) {
                    return Err(BlockchainError::TxAlreadyInBlock(tx_hash));
                }

                if !block.get_txs_hashes().contains(&tx_hash) {
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                }
                let fee = self.verify_transaction_with_hash(storage, tx, &tx_hash, false).await?;
                if let TransactionVariant::Registration = tx.get_variant() { // prevent any duplicate registration
                    if registrations.contains_key(tx.get_owner()) {
                        return Err(BlockchainError::DuplicateRegistration(tx.get_owner().clone()))
                    }
                    registrations.insert(tx.get_owner(), true);
                }
                total_fees += fee;
                cache_tx.insert(tx_hash, true);
                total_tx_size += tx.size();
            }

            if block.size() + total_tx_size > MAX_BLOCK_SIZE {
                return Err(BlockchainError::InvalidBlockSize(MAX_BLOCK_SIZE, block.size() + total_tx_size));
            }

            if cache_tx.len() != block.get_transactions().len() || cache_tx.len() != block.get_txs_hashes().len() {
                return Err(BlockchainError::InvalidBlockTxs(block.get_txs_hashes().len(), cache_tx.len()))
            }
        }

        // Miner Tx verification
        let block_reward = get_block_reward(self.get_supply());
        if !block.get_miner_tx().is_coinbase() {
            return Err(BlockchainError::InvalidMinerTx)
        }

        // miner tx don't require any signature
        if !block.get_miner_tx().verify_signature()? {
            return Err(BlockchainError::InvalidTransactionSignature)
        }

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

        for tx in block.get_transactions() { // execute all txs
            self.execute_transaction(storage, tx).await?;
        }
        self.execute_miner_tx(storage, block.get_miner_tx(), block_reward, total_fees).await?; // execute coinbase tx

        let mut tips = storage.get_tips().await?;
        for hash in block.get_tips() {
            tips.remove(hash);
        }

        let (base_hash, base_height) = self.find_common_base(storage, &tips).await?;
        let best_tip = self.find_best_tip(storage, &tips, &base_hash, base_height).await?;

        let full_order = self.generate_full_order(storage, &best_tip, &base_hash, base_height).await?;
        // TODO generate full order

        if block.get_height() > self.get_height() {
            self.height.store(block.get_height(), Ordering::Release);
            // TODO save top height
        }
        self.supply.fetch_add(block_reward, Ordering::Release);
        debug!("Adding new block '{}' with {} txs at height {}", block_hash, block.get_txs_count(), block.get_height());
        if broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                debug!("broadcast block to peers");
                p2p.broadcast_block(block.get_header(), &block_hash).await;
            }
        }

        let cumulative_difficulty = (0 as u8).to_biguint().unwrap(); // TODO
        storage.add_new_block(block, block_hash, cumulative_difficulty, self.get_supply(), self.get_burned_supply()).await // Add block to chain
    }

    pub async fn rewind_chain(&self, count: usize) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.rewind_chain_for_storage(&mut storage, count).await
    }

    // TODO missing burned supply, txs etc
    pub async fn rewind_chain_for_storage(&self, storage: &mut Storage, count: usize) -> Result<(), BlockchainError> {
        let (height, metadata) = storage.pop_blocks(self.get_height(), count as u64).await?;
        self.height.store(height, Ordering::Release);
        self.supply.store(metadata.get_supply(), Ordering::Release); // recaculate supply
        self.burned.store(metadata.get_burned_supply(), Ordering::Release);
        Ok(())
    }

    // verify the transaction and returns fees available
    async fn verify_transaction_with_hash(&self, storage: &Storage, tx: &Transaction, hash: &Hash, disable_nonce_check: bool) -> Result<u64, BlockchainError> {
        // check signature validity
        if !tx.verify_signature()? {
            return Err(BlockchainError::InvalidTransactionSignature)
        }

        match tx.get_variant() {
            TransactionVariant::Coinbase => { // don't accept any coinbase tx
                Err(BlockchainError::CoinbaseTxNotAllowed(hash.clone()))
            },
            TransactionVariant::Registration => {
                // verify this address isn't already registered
                if storage.has_account(tx.get_owner()).await? && !disable_nonce_check {
                    return Err(BlockchainError::AddressAlreadyRegistered(tx.get_owner().clone()))
                }
                
                // check validity of registration mini POW
                if !check_difficulty(&hash, REGISTRATION_DIFFICULTY)? {
                    return Err(BlockchainError::InvalidTxRegistrationPoW(hash.clone()))
                }
                Ok(0)
            }
            TransactionVariant::Normal { nonce, fee, data } => {
                let calculted_fee = calculate_tx_fee(tx.size());
                if *fee < calculted_fee { // minimum fee verification
                    return Err(BlockchainError::InvalidTxFee(calculted_fee, *fee))
                }

                {
                    let account = storage.get_account(tx.get_owner()).await?;
                    let account_nonce = account.read_nonce();
                    if !disable_nonce_check && account_nonce != *nonce { // check valid nonce
                        return Err(BlockchainError::InvalidTransactionNonce(account_nonce, *nonce))
                    }
                }

                match data {
                    TransactionData::Normal(txs) => {
                        if txs.len() == 0 { // don't accept any empty tx
                            return Err(BlockchainError::TxEmpty(hash.clone()))
                        }
                        let mut total_coins = *fee;
                        for output in txs {
                            total_coins += output.amount;
                            if output.to == *tx.get_owner() { // we can't transfer coins to ourself, why would you do that ?
                                return Err(BlockchainError::InvalidTransactionToSender(hash.clone()))
                            }
        
                            if !storage.has_account(&output.to).await? { // verify that all receivers are registered
                                return Err(BlockchainError::AddressNotRegistered(output.to.clone()))
                            }
                        }
        
                        let account = storage.get_account(tx.get_owner()).await?;
                        if account.read_balance() < total_coins { // verify that the user have enough funds
                            return Err(BlockchainError::NotEnoughFunds(tx.get_owner().clone(), total_coins))
                        }
                    }
                    TransactionData::Burn(amount) => {
                        let account = storage.get_account(tx.get_owner()).await?;
                        if account.read_balance() < amount + fee { // verify that the user have enough funds
                            return Err(BlockchainError::NotEnoughFunds(tx.get_owner().clone(), amount + fee))
                        }
                    },
                    _ => {
                        // TODO implement SC
                        return Err(BlockchainError::SmartContractTodo)
                    }
                };
                Ok(*fee)
            }
        }
    }

    async fn execute_miner_tx(&self, storage: &mut Storage, transaction: &Transaction, mut block_reward: u64, fees: u64) -> Result<(), BlockchainError> {
        if let TransactionVariant::Coinbase = transaction.get_variant() {
            if DEV_FEE_PERCENT != 0 {
                let dev_fee = block_reward * DEV_FEE_PERCENT / 100;
                let account = storage.get_account(self.get_dev_address()).await?;
                account.balance.fetch_add(dev_fee, Ordering::Relaxed);
                block_reward -= dev_fee;
            }
            let account = storage.get_account(transaction.get_owner()).await?;
            account.balance.fetch_add(block_reward + fees, Ordering::Relaxed);
            Ok(())
        } else {
            Err(BlockchainError::InvalidMinerTx)
        }
    }

    async fn execute_transaction(&self, storage: &mut Storage, transaction: &Transaction) -> Result<(), BlockchainError> {
        match transaction.get_variant() {
            TransactionVariant::Registration => {
                storage.register_account(transaction.get_owner().clone()).await?;
            }
            TransactionVariant::Coinbase => {
                // shouldn't happen due to previous check
                return Err(BlockchainError::CoinbaseTxNotAllowed(transaction.hash()))
            }
            TransactionVariant::Normal { fee, data, .. } => {
                let mut amount = 0; // total amount to be deducted
                match data {
                    TransactionData::Burn(burn_amount) => {
                        amount += burn_amount + fee;
                        self.burned.fetch_add(*burn_amount, Ordering::Relaxed);
                    }
                    TransactionData::Normal(txs) => {
                        let mut total = *fee;
                        for tx in txs {
                            let to_account = storage.get_account(&tx.to).await?; // update receiver's account
                            to_account.balance.fetch_add(tx.amount, Ordering::Relaxed);
                            total += tx.amount;
                        }
                        amount += total;
                    }
                    _ => {
                        return Err(BlockchainError::SmartContractTodo)
                    }
                };

                let account = storage.get_account(transaction.get_owner()).await?;
                account.balance.fetch_min(amount, Ordering::Relaxed);
                account.nonce.fetch_add(1, Ordering::Relaxed);
            }
        };
        Ok(())
    }
}

pub fn get_supply_at_height(height: u64) -> u64 {
    let mut supply = 0;
    for _ in 0..=height {
        supply += get_block_reward(supply);
    }
    supply
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