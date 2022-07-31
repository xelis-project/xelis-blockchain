use crate::config::{DEFAULT_P2P_BIND_ADDRESS, P2P_DEFAULT_MAX_PEERS, DEFAULT_RPC_BIND_ADDRESS, MAX_BLOCK_SIZE, EMISSION_SPEED_FACTOR, FEE_PER_KB, MAX_SUPPLY, REGISTRATION_DIFFICULTY, DEV_FEE_PERCENT, MINIMUM_DIFFICULTY, GENESIS_BLOCK, DEV_ADDRESS};
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
use super::error::BlockchainError;
use super::reader::{ReaderError, Reader};
use super::serializer::Serializer;
use super::storage::Storage;
use super::transaction::*;
use super::writer::Writer;
use std::net::SocketAddr;
use std::sync::atomic::{Ordering, AtomicU64};
use tokio::sync::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use log::{info, error, debug};
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
        self.balance.load(Ordering::Relaxed)
    }

    pub fn read_nonce(&self) -> u64 {
        self.nonce.load(Ordering::Relaxed)
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
}

pub struct Blockchain {
    height: AtomicU64, // current block height 
    supply: AtomicU64, // current circulating supply based on coins already emitted
    burned: AtomicU64, // total burned coins
    difficulty: AtomicU64, // difficulty for next block
    mempool: Mutex<Mempool>, // mempool to retrieve/add all txs
    storage: RwLock<Storage>, // storage to retrieve/add blocks
    p2p: Mutex<Option<Arc<P2pServer>>>, // P2p module
    rpc: Mutex<Option<Arc<RpcServer>>>, // Rpc module
    dev_address: PublicKey // Dev address for block fee
}

impl Blockchain {
    pub async fn new(config: Config) -> Result<Arc<Self>, BlockchainError> {
        let dev_address = Address::from_string(&DEV_ADDRESS.to_owned())?;
        let storage = Storage::new()?;
        let on_disk = storage.has_blocks();
        let (height, supply, burned, difficulty) = if on_disk {
            info!("Reading last metadata available...");
            let (height, metadata) = storage.get_top_metadata()?;
            (height, metadata.get_supply(), metadata.get_burned_supply(), metadata.get_difficulty())
        } else { (0, 0, 0, MINIMUM_DIFFICULTY) };

        let blockchain = Self {
            height: AtomicU64::new(height),
            supply: AtomicU64::new(supply),
            burned: AtomicU64::new(burned),
            difficulty: AtomicU64::new(difficulty),
            mempool: Mutex::new(Mempool::new()),
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
        storage.register_account(self.dev_address.clone()).await;

        if GENESIS_BLOCK.len() != 0 {
            info!("De-serializing genesis block...");
            match CompleteBlock::from_hex(GENESIS_BLOCK.to_owned()) {
                Ok(block) => {
                    if *block.get_miner() != self.dev_address {
                        return Err(BlockchainError::GenesisBlockMiner)
                    }
                    self.add_new_block_for_storage(&mut storage, block, true).await?;
                },
                Err(_) => return Err(BlockchainError::InvalidGenesisBlock)
            }
        } else {
            error!("No genesis block found...");
            info!("Generating a new genesis block...");
            let miner_tx = Transaction::new(self.get_dev_address().clone(), TransactionVariant::Coinbase);
            let mut block = Block::new(1, get_current_timestamp(), Hash::zero(), [0u8; 32], Immutable::Owned(miner_tx), Vec::new());
            let mut hash = block.hash();
            while self.get_height() == 0 && !check_difficulty(&hash, self.get_difficulty())? {
                block.nonce += 1;
                block.timestamp = get_current_timestamp();
                hash = block.hash();
            }
            let complete_block = CompleteBlock::new(Immutable::Owned(block), self.get_difficulty(), Vec::new());
            info!("Genesis generated & added: {}", complete_block.to_hex());
            self.add_new_block_for_storage(&mut storage, complete_block, true).await?;
        }

        Ok(())
    }

    // mine a block for current difficulty
    pub async fn mine_block(self: &Arc<Self>, key: &PublicKey) -> Result<(), BlockchainError> {
        let mut block = self.get_block_template(key.clone()).await?;
        let mut hash = block.hash();
        let mut current_height = self.get_height();
        while !check_difficulty(&hash, self.get_difficulty())? {
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

    pub fn get_height(&self) -> u64 {
        self.height.load(Ordering::Relaxed)
    }

    pub fn get_p2p(&self) -> &Mutex<Option<Arc<P2pServer>>> {
        &self.p2p
    }

    pub fn get_difficulty(&self) -> u64 {
        self.difficulty.load(Ordering::Relaxed)
    }

    pub fn get_supply(&self) -> u64 {
        self.supply.load(Ordering::Relaxed)
    }

    pub fn get_burned_supply(&self) -> u64 {
        self.burned.load(Ordering::Relaxed)
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

    pub fn get_mempool(&self) -> &Mutex<Mempool> {
        &self.mempool
    }

    pub async fn add_tx_to_mempool(&self, tx: Transaction, broadcast: bool) -> Result<(), BlockchainError> {
        let hash = tx.hash();
        let mut mempool = self.mempool.lock().await;
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
        mempool.add_tx_with_fee(hash, tx, fee)
    }

    pub async fn get_block_template(&self, address: PublicKey) -> Result<Block, BlockchainError> {
        let coinbase_tx = Transaction::new(address, TransactionVariant::Coinbase);
        let extra_nonce: [u8; 32] = rand::thread_rng().gen::<[u8; 32]>(); // generate random bytes
        let mut block = Block::new(self.get_height() + 1, get_current_timestamp(), self.get_top_block_hash().await?, extra_nonce, Immutable::Owned(coinbase_tx), Vec::new());
        let mempool = self.mempool.lock().await;
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
        let mempool = self.mempool.lock().await;
        for hash in &block.txs_hashes {
            let tx = mempool.view_tx(hash)?; // at this point, we don't want to lose/remove any tx, we clone it only
            transactions.push(Immutable::Owned(tx.clone())); // TODO maybe use a Rc ?
        }
        let complete_block = CompleteBlock::new(Immutable::Owned(block), self.get_difficulty(), transactions);
        Ok(complete_block)
    }

    pub async fn check_validity(&self) -> Result<(), BlockchainError> {
        /*let storage = self.storage.lock().await;
        let blocks = storage.get_blocks();
        if self.get_height() != blocks.len() as u64 {
            return Err(BlockchainError::InvalidBlockHeight(self.get_height(), blocks.len() as u64))
        }

        // TODO re calculate ALL accounts balances
        let mut circulating_supply = 0;
        for (height, block) in blocks.iter().enumerate() {
            let hash = block.hash();
            if block.get_height() != height as u64 {
                debug!("Invalid block height for block {}, got {} but expected {}", block, block.get_height(), height);
                return Err(BlockchainError::InvalidBlockHeight(block.get_height(), height as u64))
            }

            if block.get_height() != 1 { // if not genesis, check parent block
                let previous_hash = storage.get_block_at_height(block.get_height() - 1)?.hash();
                if previous_hash != *block.get_previous_hash() {
                    debug!("Invalid previous block hash, expected {} got {}", previous_hash, block.get_previous_hash());
                    return Err(BlockchainError::InvalidHash(previous_hash, block.get_previous_hash().clone()));
                }
            }

            let txs_len = block.get_transactions().len();
            let txs_hashes_len = block.get_txs_hashes().len();
            if txs_len != txs_hashes_len {
                return Err(BlockchainError::InvalidBlockTxs(txs_hashes_len, txs_len));
            }

            if !check_difficulty(&hash, self.get_difficulty())? {
                return Err(BlockchainError::InvalidDifficulty)
            }

            if !block.get_miner_tx().is_coinbase() || !block.get_miner_tx().verify_signature()? {
                return Err(BlockchainError::InvalidMinerTx)
            }

            let reward = get_block_reward(circulating_supply);
            for tx in block.get_transactions() {
                let tx_hash = tx.hash();
                if !tx.is_coinbase() {
                    self.verify_transaction_with_hash(&storage, tx, &tx_hash, true)?; // TODO check when account have no more funds
                } else {
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                }

                if !block.get_txs_hashes().contains(&tx_hash) { // check if tx is in txs hashes
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                }
            }
            circulating_supply += reward;
        }

        let mut total_supply_from_accounts = 0;
        /*for (_, account) in storage.get_accounts() {
            total_supply_from_accounts += account.balance;
        }*/

        if circulating_supply != self.get_supply() - self.get_burned_supply() {
            return Err(BlockchainError::InvalidCirculatingSupply(circulating_supply, self.get_supply()));
        }

        if total_supply_from_accounts != circulating_supply {
            return Err(BlockchainError::InvalidCirculatingSupply(total_supply_from_accounts, self.get_supply()));
        }*/
        Ok(())
    }

    pub async fn add_new_block(&self, block: CompleteBlock, broadcast: bool) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.add_new_block_for_storage(&mut storage, block, broadcast).await
    }

    pub async fn add_new_block_for_storage(&self, storage: &mut Storage, block: CompleteBlock, broadcast: bool) -> Result<(), BlockchainError> {
        let current_height = self.get_height();
        let current_difficulty = self.get_difficulty();
        let block_hash = block.hash();
        if current_height + 1 != block.get_height() {
            return Err(BlockchainError::InvalidBlockHeight(current_height + 1, block.get_height()));
        } else if !check_difficulty(&block_hash, current_difficulty)? {
            return Err(BlockchainError::InvalidDifficulty);
        } else if block.get_timestamp() > get_current_timestamp() { // TODO accept a latency of max 30s
            return Err(BlockchainError::TimestampIsInFuture(get_current_timestamp(), block.get_timestamp()));
        } else if current_height != 0 { // if it's not the genesis block
            let previous_block = storage.get_block_at_height(current_height).await?;
            let previous_hash = previous_block.hash();
            if previous_hash != *block.get_previous_hash() {
                return Err(BlockchainError::InvalidPreviousBlockHash(previous_hash, block.get_previous_hash().clone()));
            }
            if previous_block.get_timestamp() > block.get_timestamp() { // block timestamp can't be less than previous block.
                return Err(BlockchainError::TimestampIsLessThanParent(block.get_timestamp()));
            }
            debug!("Block Time for this block is: {:.2}s", (block.get_timestamp() - previous_block.get_timestamp()) as f64 / 1000f64);
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
        let mut mempool = self.mempool.lock().await;
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

        if current_height > 2 { // re calculate difficulty
            let top_block = storage.get_top_complete_block().await?;
            let difficulty = calculate_difficulty(&top_block, &block, current_difficulty);
            self.difficulty.store(difficulty, Ordering::Relaxed);
        }

        self.height.store(block.get_height(), Ordering::Relaxed);
        self.supply.fetch_add(block_reward, Ordering::Relaxed);
        debug!("Adding new block '{}' with {} txs at height {}", block_hash, block.get_txs_count(), block.get_height());
        if broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                debug!("broadcast block to peers");
                p2p.broadcast_block(&block, &block_hash).await;
            }
        }

        storage.add_new_block(block, block_hash, self.get_supply(), self.get_burned_supply()).await // Add block to chain
    }

    pub async fn rewind_chain(&self, count: usize) -> Result<(), BlockchainError> {
        let mut storage = self.storage.write().await;
        self.rewind_chain_for_storage(&mut storage, count).await
    }

    // TODO missing burned supply, txs etc
    pub async fn rewind_chain_for_storage(&self, storage: &mut Storage, count: usize) -> Result<(), BlockchainError> {
        let top_height = storage.pop_blocks(count)?;
        self.height.store(top_height, Ordering::Relaxed);
        self.supply.store(get_supply_at_height(top_height), Ordering::Relaxed); // recaculate supply
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
                storage.register_account(transaction.get_owner().clone()).await;
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