use crate::config::{MAX_BLOCK_SIZE, EMISSION_SPEED_FACTOR, FEE_PER_KB, MAX_SUPPLY, REGISTRATION_DIFFICULTY, DEV_FEE_PERCENT, MINIMUM_DIFFICULTY, GENESIS_BLOCK, DEV_ADDRESS};
use crate::crypto::hash::{Hash, Hashable};
use crate::globals::get_current_time;
use crate::crypto::key::PublicKey;
use crate::p2p::server::P2pServer;
use crate::rpc::RpcServer;
use super::difficulty::{check_difficulty, calculate_difficulty};
use super::block::{Block, CompleteBlock};
use super::mempool::{Mempool, SortedTx};
use super::error::BlockchainError;
use super::serializer::Serializer;
use super::storage::Storage;
use super::transaction::*;
use std::sync::atomic::{Ordering, AtomicU64};
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use log::{info, error, debug};
use rand::Rng;

#[derive(serde::Serialize)]
pub struct Account {
    balance: u64,
    nonce: u64
}

impl Account {
    pub fn new(balance: u64, nonce: u64) -> Self {
        Self {
            balance,
            nonce
        }
    }

    pub fn get_balance(&self) -> u64 {
        self.balance
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }
}

pub struct Blockchain {
    height: AtomicU64, // current block height 
    supply: AtomicU64, // current circulating supply based on coins already emitted
    difficulty: AtomicU64, // difficulty for next block
    mempool: Mutex<Mempool>, // mempool to retrieve/add all txs
    storage: Mutex<Storage>, // storage to retrieve/add blocks
    p2p: Mutex<Option<Arc<P2pServer>>>, // P2p module
    rpc: Mutex<Option<Arc<RpcServer>>>, // Rpc module
    dev_address: PublicKey // Dev address for block fee
}

impl Blockchain {
    pub async fn new(tag: Option<String>, max_peers: usize, p2p_address: String, rpc_address: String) -> Result<Arc<Self>, BlockchainError> {
        let dev_address = PublicKey::from_address(&DEV_ADDRESS.to_owned())?;
        let blockchain = Self {
            height: AtomicU64::new(0),
            supply: AtomicU64::new(0),
            difficulty: AtomicU64::new(MINIMUM_DIFFICULTY),
            mempool: Mutex::new(Mempool::new()),
            storage: Mutex::new(Storage::new()),
            p2p: Mutex::new(None),
            rpc: Mutex::new(None),
            dev_address: dev_address
        };
        // TODO Read blockchain from disk if exists
        // include genesis block
        blockchain.create_genesis_block().await?;

        let arc = Arc::new(blockchain);
        // create P2P Server
        {
            let p2p = P2pServer::new(tag, max_peers, p2p_address, Arc::clone(&arc))?;
            *arc.p2p.lock().await = Some(p2p);
        }

        // create RPC Server
        {
            let server = RpcServer::new(rpc_address, Arc::clone(&arc)).await?;
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
        if GENESIS_BLOCK.len() != 0 {
            info!("De-serializing genesis block...");
            match CompleteBlock::from_hex(GENESIS_BLOCK.to_owned()) {
                Ok(block) => {
                    let dev_address = self.dev_address.clone();
                    if *block.get_miner() != dev_address {
                        return Err(BlockchainError::GenesisBlockMiner)
                    }
                    self.storage.lock().await.register_account(dev_address);
                    self.add_new_block(block, true).await?;
                },
                Err(_) => return Err(BlockchainError::InvalidGenesisBlock)
            }
        } else {
            error!("No genesis block found...");
            info!("Generating a new genesis block...");
            let coinbase = CoinbaseTx {
                block_reward: get_block_reward(0),
                fee_reward: 0
            };
            let miner_tx = Transaction::new(0, TransactionData::Coinbase(coinbase), self.get_dev_address().clone());
            let mut block = Block::new(0, get_current_time(), Hash::zero(), [0u8; 32], miner_tx, Vec::new());
            let mut hash = block.hash();
            while self.get_height() == 0 && !check_difficulty(&hash, self.get_difficulty())? {
                block.nonce += 1;
                block.timestamp = get_current_time();
                hash = block.hash();
            }
            let complete_block = CompleteBlock::new(block, self.get_difficulty(), Vec::new());
            info!("Genesis generated & added: {}", complete_block.to_hex());
            self.add_new_block(complete_block, true).await?;
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
            block.timestamp = get_current_time();
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

    pub fn get_dev_address(&self) -> &PublicKey {
        &self.dev_address
    }

    pub fn get_storage(&self) -> &Mutex<Storage> {
        &self.storage
    }

    pub async fn get_top_block_hash(&self) -> Hash {
        self.storage.lock().await.get_top_block_hash().clone()
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

        let storage = self.storage.lock().await;
        self.verify_transaction_with_hash(&storage, &tx, &hash, false)?;
        if broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                p2p.broadcast_tx(&tx).await;
            }
        }

        mempool.add_tx(hash, tx)
    }

    pub async fn get_block_template(&self, address: PublicKey) -> Result<Block, BlockchainError> {
        let coinbase_tx = Transaction::new(0, TransactionData::Coinbase(CoinbaseTx {
            block_reward: get_block_reward(self.get_supply()),
            fee_reward: 0,
        }), address);
        let extra_nonce: [u8; 32] = rand::thread_rng().gen::<[u8; 32]>();
        let mut block = Block::new(self.get_height() + 1, get_current_time(), self.get_top_block_hash().await, extra_nonce, coinbase_tx, Vec::new());
        let mut total_fee = 0;
        let mempool = self.mempool.lock().await;
        let txs: &Vec<SortedTx> = mempool.get_sorted_txs();
        let mut tx_size = 0;
        for tx in txs {
            tx_size += tx.get_size();
            if block.size() + tx_size > MAX_BLOCK_SIZE {
                break;
            }

            total_fee += tx.get_fee();
            block.txs_hashes.push(tx.get_hash().clone());
        }

        match block.miner_tx.get_mut_data() {
            TransactionData::Coinbase(ref mut data) => {
                data.fee_reward = total_fee;
            },
            _ => {}
        }

        Ok(block)
    }

    pub async fn build_complete_block_from_block(&self, block: Block) -> Result<CompleteBlock, BlockchainError> {
        let mut transactions: Vec<Transaction> = vec![];
        let mempool = self.mempool.lock().await;
        for hash in &block.txs_hashes {
            let tx = mempool.view_tx(hash)?; // at this point, we don't want to lose/remove any tx, we clone it only
            transactions.push(tx.clone());
        }
        let complete_block = CompleteBlock::new(block, self.get_difficulty(), transactions);
        Ok(complete_block)
    }

    pub async fn check_validity(&self) -> Result<(), BlockchainError> {
        let storage = self.storage.lock().await;
        let blocks = storage.get_blocks();
        if self.get_height() != blocks.len() as u64 {
            return Err(BlockchainError::InvalidBlockHeight(self.get_height(), blocks.len() as u64))
        }

        let mut circulating_supply = 0;
        for (height, block) in blocks.iter().enumerate() {
            let hash = block.hash();
            if block.get_height() != height as u64 {
                debug!("Invalid block height for block {}, got {} but expected {}", block, block.get_height(), height);
                return Err(BlockchainError::InvalidBlockHeight(block.get_height(), height as u64))
            }

            if block.get_height() != 0 { // if not genesis, check parent block
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

            let coinbase_tx = match block.get_miner_tx().get_data() {
                TransactionData::Coinbase(tx) => tx,
                _ => return Err(BlockchainError::InvalidMinerTx)
            };
            let reward = get_block_reward(circulating_supply);
            if coinbase_tx.block_reward != reward {
                return Err(BlockchainError::InvalidBlockReward(coinbase_tx.block_reward, reward))
            }

            let mut fees: u64 = 0;
            for tx in block.get_transactions() {
                let tx_hash = tx.hash();
                if !tx.is_coinbase() {
                    self.verify_transaction(&storage, tx, true)?;
                } else {
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                }

                if !block.get_txs_hashes().contains(&tx_hash) { // check if tx is in txs hashes
                    return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                }

                fees += tx.get_fee();
            }

            if fees != coinbase_tx.fee_reward {
                return Err(BlockchainError::InvalidBlockReward(coinbase_tx.block_reward + coinbase_tx.fee_reward, reward + fees))
            }

            circulating_supply += reward;
        }

        let mut total_supply_from_accounts = 0;
        for (_, account) in storage.get_accounts() {
            total_supply_from_accounts += account.balance;
        }

        if circulating_supply != self.get_supply() {
            return Err(BlockchainError::InvalidCirculatingSupply(circulating_supply, self.get_supply()));
        }

        if total_supply_from_accounts != self.get_supply() {
            return Err(BlockchainError::InvalidCirculatingSupply(total_supply_from_accounts, self.get_supply()));
        }

        Ok(())
    }

    pub async fn add_new_block(&self, block: CompleteBlock, broadcast: bool) -> Result<(), BlockchainError> {
        let mut storage = self.storage.lock().await;
        self.add_new_block_for_storage(&mut storage, block, broadcast).await
    }

    pub async fn add_new_block_for_storage(&self, storage: &mut Storage, block: CompleteBlock, broadcast: bool) -> Result<(), BlockchainError> {
        let current_height = self.get_height();
        let current_difficulty = self.get_difficulty();
        let block_hash = block.hash();
        if storage.has_blocks() && current_height + 1 != block.get_height() {
            return Err(BlockchainError::InvalidBlockHeight(current_height + 1, block.get_height()));
        } else if !check_difficulty(&block_hash, current_difficulty)? {
            return Err(BlockchainError::InvalidDifficulty);
        } else if block.get_timestamp() > get_current_time() { // TODO accept a latency of max 30s
            return Err(BlockchainError::TimestampIsInFuture(get_current_time(), block.get_timestamp()));
        } else if current_height != 0 && storage.has_blocks() { // TODO Block exist
            let previous_block = storage.get_block_at_height(current_height)?;
            let previous_hash = previous_block.hash();
            if previous_hash != *block.get_previous_hash() {
                return Err(BlockchainError::InvalidPreviousBlockHash(block.get_previous_hash().clone(), previous_hash));
            }
            if previous_block.get_timestamp() > block.get_timestamp() { // block timestamp can't be less than previous block.
                return Err(BlockchainError::TimestampIsLessThanParent(block.get_timestamp()));
            }
            debug!("Block Time for this block is: {}s", block.get_timestamp() - previous_block.get_timestamp());
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

                match tx.get_data() {
                    TransactionData::Coinbase(_) => {
                        return Err(BlockchainError::InvalidTxInBlock(tx_hash))
                    }
                    TransactionData::Registration => {
                        if registrations.contains_key(tx.get_sender()) {
                            return Err(BlockchainError::DuplicateRegistration(tx.get_sender().clone()))
                        }
                        registrations.insert(tx.get_sender(), true);
                    }
                    _ => {}
                };

                self.verify_transaction_with_hash(&storage, tx, &tx_hash, false)?;
                cache_tx.insert(tx_hash, true);
                total_fees += tx.get_fee();
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
        match block.get_miner_tx().get_data() {
            TransactionData::Coinbase(data) => { // reward contains block reward + fees from all txs included in this block
                if !storage.has_account(block.get_miner_tx().get_sender()) {
                    return Err(BlockchainError::AddressNotRegistered(block.get_miner_tx().get_sender().clone()));
                }

                if block.get_miner_tx().get_fee() != 0 { // coinbase tx don't pay fee, if we have fee, they try to generate unauthorized coins
                    return Err(BlockchainError::InvalidTxFee(0, block.get_miner_tx().get_fee()))
                }

                if block.get_miner_tx().has_signature() { // Coinbase tx should not be signed (there is no sender, why signing it ?)
                    return Err(BlockchainError::InvalidTransactionSignature)
                }

                if data.block_reward != block_reward || data.fee_reward != total_fees {
                    return Err(BlockchainError::InvalidBlockReward(block_reward + total_fees, data.block_reward + data.fee_reward))
                }

                if data.fee_reward != total_fees {
                    return Err(BlockchainError::InvalidFeeReward(total_fees, data.fee_reward))
                }
            }
            _ => {
                return Err(BlockchainError::InvalidMinerTx)
            }
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
            self.execute_transaction(storage, tx)?;
        }
        self.execute_transaction(storage, block.get_miner_tx())?; // execute coinbase tx

        if current_height > 2 { // re calculate difficulty
            let difficulty = calculate_difficulty(storage.get_top_block()?, &block);
            self.difficulty.store(difficulty, Ordering::Relaxed);
        }

        self.height.store(block.get_height(), Ordering::Relaxed);
        self.supply.fetch_add(block_reward, Ordering::Relaxed);
        debug!("Adding new block '{}' at height {}", block_hash, block.get_height());
        if block.get_height() != 0 && broadcast {
            if let Some(p2p) = self.p2p.lock().await.as_ref() {
                debug!("broadcast block to peers");
                p2p.broadcast_block(&block).await;
            }
        }

        storage.add_new_block(block, block_hash); // Add block to chain
        Ok(())
    }

    pub async fn rewind_chain(&self, count: usize) -> Result<(), BlockchainError> {
        let mut storage = self.storage.lock().await;
        self.rewind_chain_for_storage(&mut storage, count).await
    }

    pub async fn rewind_chain_for_storage(&self, storage: &mut Storage, count: usize) -> Result<(), BlockchainError> {
        let top_height = storage.pop_blocks(count)?;
        self.height.store(top_height, Ordering::Relaxed);
        self.supply.store(get_supply_at_height(top_height), Ordering::Relaxed); // recaculate supply
        Ok(())
    }

    fn verify_transaction(&self, storage: &Storage, tx: &Transaction, disable_nonce_check: bool) -> Result<(), BlockchainError> {
        self.verify_transaction_with_hash(storage, tx, &tx.hash(), disable_nonce_check)
    }

    fn verify_transaction_with_hash(&self, storage: &Storage, tx: &Transaction, hash: &Hash, disable_nonce_check: bool) -> Result<(), BlockchainError> {
        if tx.require_signature() && (!tx.has_signature() || !tx.verify_signature()) { // signature verification for tx types required
            return Err(BlockchainError::InvalidTransactionSignature)
        }

        let is_registration = tx.is_registration();
        if is_registration || tx.is_coinbase() {
            if tx.get_fee() != 0 { // coinbase & registration tx cannot have fee
                return Err(BlockchainError::InvalidTxFee(0, tx.get_fee()))
            }
        } else {
            let fee = calculate_tx_fee(tx.size());
            if tx.get_fee() < fee { // minimum fee verification
                return Err(BlockchainError::InvalidTxFee(fee, tx.get_fee()))
            }
        }

        if is_registration {
            if storage.has_account(tx.get_sender()) && !disable_nonce_check {
                return Err(BlockchainError::AddressAlreadyRegistered(tx.get_sender().clone()))
            }

            if !check_difficulty(&hash, REGISTRATION_DIFFICULTY)? {
                return Err(BlockchainError::InvalidTxRegistrationPoW(hash.clone()))
            }

            return Ok(())
        }

        let account = storage.get_account(tx.get_sender())?;
        if !disable_nonce_check && account.nonce != tx.get_nonce() {
            return Err(BlockchainError::InvalidTransactionNonce(account.nonce, tx.get_nonce()))
        }

        match tx.get_data() {
            TransactionData::Normal(txs) => {
                if txs.len() == 0 {
                    return Err(BlockchainError::TxEmpty(hash.clone()))
                }
                let mut total_coins = tx.get_fee();
                for output in txs {
                    total_coins += output.amount;
                    if output.to == *tx.get_sender() { // we can't transfer coins to ourself, why would you do that ?
                        return Err(BlockchainError::InvalidTransactionToSender(hash.clone()))
                    }

                    if !storage.has_account(&output.to) { // verify that all receivers are registered
                        return Err(BlockchainError::AddressNotRegistered(output.to.clone()))
                    }
                }

                if account.balance < total_coins {
                    return Err(BlockchainError::NotEnoughFunds(tx.get_sender().clone(), total_coins))
                }
            }
            TransactionData::Burn(amount) => {
                if account.balance < amount + tx.get_fee() {
                    return Err(BlockchainError::NotEnoughFunds(tx.get_sender().clone(), amount + tx.get_fee()))
                }
            }
            TransactionData::Coinbase(_) => {
                return Err(BlockchainError::CoinbaseTxNotAllowed(hash.clone()));
            }
            _ => {
                panic!("Not implemented yet")
            }
        };

        Ok(())
    }

    fn execute_transaction(&self, storage: &mut Storage, transaction: &Transaction) -> Result<(), BlockchainError> {
        let mut amount = 0;
        match transaction.get_data() {
            TransactionData::Burn(burn_amount) => {
                amount += burn_amount + transaction.get_fee();
                //self.supply = self.supply - burn_amount; // by burning an amount, this amount can still be regenerated through block reward, should we prevent this ?
            }
            TransactionData::Normal(txs) => {
                let mut total = transaction.get_fee();
                for tx in txs {
                    let to_account = storage.get_mut_account(&tx.to)?;
                    to_account.balance += tx.amount;
                    total += tx.amount;
                }

                amount += total;
            }
            TransactionData::Registration => {
                storage.register_account(transaction.get_sender().clone());

                return Ok(())
            }
            TransactionData::Coinbase(data) => {
                let mut block_reward = data.block_reward;
                if DEV_FEE_PERCENT != 0 {
                    let dev_fee = block_reward * DEV_FEE_PERCENT / 100;
                    let account = storage.get_mut_account(self.get_dev_address())?;
                    account.balance += dev_fee;
                    block_reward -= dev_fee;
                }

                let account = storage.get_mut_account(transaction.get_sender())?;
                account.balance += block_reward + data.fee_reward;

                return Ok(()) // return now to prevent the nonce increment
            }
            _ => {
                panic!("not implemented")
            }
        };

        let account = storage.get_mut_account(transaction.get_sender())?;
        account.balance -= amount;
        account.nonce += 1;

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