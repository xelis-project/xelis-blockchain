use crate::globals::get_current_time;
use crate::block::Block;
use crate::difficulty::{check_difficulty, calculate_difficulty};
use crate::config::{MAX_BLOCK_SIZE, EMISSION_SPEED_FACTOR, FEE_PER_KB, MAX_SUPPLY, REGISTRATION_DIFFICULTY, DEV_FEE_PERCENT, MINIMUM_DIFFICULTY};
use crate::transaction::*;
use std::collections::HashMap;
use crate::crypto::key::PublicKey;
use crate::crypto::hash::{Hash, Hashable};
use crate::crypto::bech32::Bech32Error;

pub enum BlockchainError {
    TimestampIsLessThanParent(u64),
    TimestampIsInFuture(u64, u64), //left is expected, right is got
    InvalidBlockHeight(u64, u64),
    InvalidDifficulty(u64, u64),
    InvalidHash(Hash, Hash),
    InvalidPreviousBlockHash(Hash, Hash),
    InvalidBlockSize(usize, usize),
    TxNotFound(Hash),
    TxAlreadyInMempool(Hash),
    TxEmpty(Hash),
    DuplicateRegistration(PublicKey), //address
    InvalidTxFee(u64, u64),
    AddressNotRegistered(PublicKey),
    AddressAlreadyRegistered(PublicKey),
    NotEnoughFunds(PublicKey, u64),
    CoinbaseTxNotAllowed(Hash),
    MultipleCoinbaseTx(u64),
    InvalidBlockReward(u64, u64),
    InvalidFeeReward(u64, u64),
    InvalidCirculatingSupply(u64, u64),
    InvalidTxRegistrationPoW(Hash),
    InvalidTransactionNonce(u64, u64),
    InvalidTransactionToSender(Hash),
    ErrorOnBech32(Bech32Error),
    InvalidTransactionSignature,
    DifficultyCannotBeZero,
    DifficultyErrorOnConversion,
}

#[derive(serde::Serialize)]
pub struct Account {
    balance: u64,
    nonce: u64
}

impl Account {
    pub fn get_balance(&self) -> u64 {
        self.balance
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }
}

#[derive(serde::Serialize)]
pub struct Blockchain {
    blocks: Vec<Block>,
    height: u64,
    supply: u64,
    top_hash: Hash,
    difficulty: u64,
    mempool: HashMap<Hash, Transaction>,
    accounts: HashMap<PublicKey, Account>,
    dev_address: PublicKey
}

impl Blockchain {

    pub fn new(dev_key: PublicKey) -> Self {
        let mut blockchain = Blockchain {
            blocks: vec![],
            height: 0,
            supply: 0,
            top_hash: Hash::zero(),
            difficulty: MINIMUM_DIFFICULTY,
            mempool: HashMap::new(),
            accounts: HashMap::new(),
            dev_address: dev_key
        };

        blockchain.register_account(&dev_key);

        blockchain
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn add_tx_to_mempool(&mut self, tx: Transaction) -> Result<(), BlockchainError> {
        let hash = tx.hash();
        if self.mempool.contains_key(&hash) {
            return Err(BlockchainError::TxAlreadyInMempool(hash))
        }

        self.verify_transaction_with_hash(&tx, &hash, false)?;

        println!("Adding new transaction to mempool: {}", hash);
        self.mempool.insert(hash, tx);

        Ok(())
    }

    pub fn register_account(&mut self, pub_key: &PublicKey) {
        self.accounts.insert(pub_key.clone(), Account {
            balance: 0,
            nonce: 0
        });
    }

    pub fn has_account(&self, account: &PublicKey) -> bool {
        self.accounts.contains_key(account)
    }

    pub fn get_account(&self, account: &PublicKey) -> Result<&Account, BlockchainError> {
        match self.accounts.get(account) {
            Some(v) => Ok(v),
            None => Err(BlockchainError::AddressNotRegistered(account.clone()))
        }
    }

    pub fn get_mut_account(&mut self, account: &PublicKey) -> Result<&mut Account, BlockchainError> {
        match self.accounts.get_mut(account) {
            Some(v) => Ok(v),
            None => Err(BlockchainError::AddressNotRegistered(account.clone()))
        }
    }

    pub fn get_block_template(&self, address: PublicKey) -> Block {
        let mut block_reward = get_block_reward(self.supply);
        let mut block = Block::new(self.height, get_current_time(), self.top_hash.clone(), self.difficulty, block_reward, [0; 32], vec![]);
        let mut transactions: Vec<Transaction> = self.mempool.values().cloned().collect();
        transactions.sort_by(| a, b | a.get_fee().cmp(&b.get_fee())); //TODO verify the result

        if DEV_FEE_PERCENT != 0 {
            let dev_reward = block_reward * DEV_FEE_PERCENT / 100;
            let dev_fee_tx = Transaction::new(self.height, TransactionData::Coinbase(CoinbaseTx {
                amount: dev_reward,
            }), self.dev_address.clone());
            block.transactions.push(dev_fee_tx);
            block_reward -= dev_reward;
        }

        let mut fee = 0;
        while transactions.len() > 0 && block.size() < MAX_BLOCK_SIZE { //TODO add coinbase tx in block size
            let tx = transactions.remove(0);
            fee += tx.get_fee();
            block.transactions.push(tx);
        }

        let coinbase_tx = Transaction::new(self.height, TransactionData::Coinbase(CoinbaseTx {
            amount: block_reward + fee,
        }), address);
        block.transactions.push(coinbase_tx);
        block
    }

    pub fn check_validity(&self) -> Result<(), BlockchainError> {
        if self.height != self.blocks.len() as u64 {
            return Err(BlockchainError::InvalidBlockHeight(self.height, self.blocks.len() as u64))
        }

        let mut circulating_supply = 0;
        for (height, block) in self.blocks.iter().enumerate() {
            let hash = block.hash();
            if hash != block.hash {
                println!("invalid block hash for {}", block);
                return Err(BlockchainError::InvalidHash(block.hash.clone(), hash))
            }

            if block.height != height as u64 {
                println!("Invalid block height for block {}, got {} but expected {}", block, block.height, height);
                return Err(BlockchainError::InvalidBlockHeight(block.height, height as u64))
            }

            if block.height != 0 {
                let previous = &self.blocks[height - 1];
                if previous.hash != block.previous_hash {
                    println!("Invalid previous block hash, expected {} got {}", previous.hash, block.previous_hash);
                    return Err(BlockchainError::InvalidHash(previous.hash.clone(), block.previous_hash.clone()));
                }
            }

            for tx in &block.transactions {
                if !tx.is_coinbase() {
                    self.verify_transaction(tx, true)?;
                }

                if let TransactionData::Burn(data) = tx.get_data() {
                    circulating_supply -= data.amount;
                }
            }

            circulating_supply += block.reward;
        }

        let mut total_supply_from_accounts = 0;
        for (_, account) in &self.accounts {
            total_supply_from_accounts += account.balance;
        }

        if circulating_supply != self.supply || total_supply_from_accounts != self.supply {
            return Err(BlockchainError::InvalidCirculatingSupply(circulating_supply, self.supply));
        }

        Ok(())
    }

    pub fn add_new_block(&mut self, block: Block) -> Result<(), BlockchainError> {
        let block_hash = block.hash();
        if self.height != block.height {
            return Err(BlockchainError::InvalidBlockHeight(block.height, block.height));
        } else if block.size() > MAX_BLOCK_SIZE {
            return Err(BlockchainError::InvalidBlockSize(MAX_BLOCK_SIZE, block.size()));
        } else if block_hash != block.hash {
            return Err(BlockchainError::InvalidHash(block_hash, block.hash));
        } else if !check_difficulty(&block_hash, block.difficulty)? || block.difficulty != self.difficulty {
            return Err(BlockchainError::InvalidDifficulty(self.difficulty, block.difficulty));
        } else if block.timestamp > get_current_time() {
            return Err(BlockchainError::TimestampIsInFuture(get_current_time(), block.timestamp));
        } else if self.height != 0 {
            let previous_block = &self.blocks[(self.height as usize) - 1];
            if previous_block.hash != block.previous_hash {
                return Err(BlockchainError::InvalidPreviousBlockHash(block.previous_hash, previous_block.hash.clone()));
            }
            if previous_block.timestamp > block.timestamp {
                return Err(BlockchainError::TimestampIsLessThanParent(block.timestamp));
            }
            println!("Block Time for this block is: {}s", block.timestamp - previous_block.timestamp);
        }

        let mut txs_hashes: Vec<Hash> = vec![];
        let mut txs_coinbase: Vec<&Transaction> = vec![];
        {
            let block_reward = get_block_reward(self.supply); //block reward verification
            if block.reward != block_reward {
                return Err(BlockchainError::InvalidBlockReward(block_reward, block.reward));
            }

            //Transaction verification
            let mut coinbase_count = 0;
            let mut expected_fee = 0;
            let mut coinbase_tx_fee = 0;
            let mut coinbase_reward = 0;
            let mut registrations: HashMap<PublicKey, bool> = HashMap::new();
            for tx in &block.transactions {
                match tx.get_data() {
                    TransactionData::Coinbase(data) => { //TODO rework coinbase system
                        if !self.has_account(tx.get_sender()) {
                            return Err(BlockchainError::AddressNotRegistered(tx.get_sender().clone()));
                        }

                        if *tx.get_fee() != 0 {
                            return Err(BlockchainError::InvalidTxFee(0, *tx.get_fee()))
                        }

                        if tx.has_signature() {
                            return Err(BlockchainError::InvalidTransactionSignature) //Coinbase tx should not be signed (there is no sender, why signing it ?)
                        }

                        coinbase_count += 1;
                        if DEV_FEE_PERCENT != 0 {
                            let calculated_reward = block_reward * DEV_FEE_PERCENT / 100;
                            if calculated_reward != data.amount { //that's not devfee then
                                let base_reward = block_reward - (block_reward * DEV_FEE_PERCENT / 100);
                                if data.amount < base_reward {
                                    return Err(BlockchainError::InvalidBlockReward(base_reward, data.amount))
                                }
                                coinbase_tx_fee = data.amount - base_reward;
                            }
                        }

                        coinbase_reward += data.amount;
                        txs_coinbase.push(&tx);
                        continue;
                    }
                    TransactionData::Registration => {
                        if registrations.contains_key(tx.get_sender()) {
                            return Err(BlockchainError::DuplicateRegistration(tx.get_sender().clone()))
                        }
                        registrations.insert(tx.get_sender().clone(), true);
                    }
                    _ => {
                        expected_fee += tx.get_fee();
                    }
                };

                let hash = tx.hash();
                if !self.mempool.contains_key(&hash) {
                    return Err(BlockchainError::TxNotFound(hash));
                }

                self.verify_transaction_with_hash(tx, &hash, false)?;
                txs_hashes.push(hash);
                
            }

            if (coinbase_count != 1 && DEV_FEE_PERCENT == 0) || (coinbase_count != 2 && DEV_FEE_PERCENT != 0) {
                return Err(BlockchainError::MultipleCoinbaseTx(coinbase_count));
            }

            if coinbase_tx_fee != expected_fee {
                return Err(BlockchainError::InvalidFeeReward(expected_fee, coinbase_tx_fee));
            }

            let expected_reward = expected_fee + block.reward;
            if expected_reward != coinbase_reward {
                return Err(BlockchainError::InvalidBlockReward(expected_reward, coinbase_reward));
            }
        }

        //Transaction execution
        for hash in txs_hashes {
            if let Some(tx) = self.mempool.remove(&hash) {
                self.execute_transaction(&tx)?;
            } else {
                return Err(BlockchainError::TxNotFound(hash));
            }
        }

        for coinbase in txs_coinbase {
            self.execute_transaction(&coinbase)?;
        }

        self.height += 1;
        self.top_hash = block_hash;
        self.supply += block.reward;
        println!("New block added to blockchain: {}", block);
        self.blocks.push(block);
        self.difficulty = calculate_difficulty(&self.blocks);
        Ok(())
    }

    fn verify_transaction(&self, tx: &Transaction, disable_nonce_check: bool) -> Result<(), BlockchainError> {
        self.verify_transaction_with_hash(tx, &tx.hash(), disable_nonce_check)
    }

    //We return the hash passed in argument to avoid the same hash calculation several times
    fn verify_transaction_with_hash(&self, tx: &Transaction, hash: &Hash, disable_nonce_check: bool) -> Result<(), BlockchainError> {
        if tx.is_registration() {
            if self.has_account(tx.get_sender()) && !disable_nonce_check {
                return Err(BlockchainError::AddressAlreadyRegistered(tx.get_sender().clone()))
            }

            if !check_difficulty(&hash, REGISTRATION_DIFFICULTY)? {
                return Err(BlockchainError::InvalidTxRegistrationPoW(hash.clone()))
            }

            return Ok(())
        }

        match tx.get_signature() {
            Some(signature) => {
                if !tx.get_sender().verify_signature(&hash, signature) && !tx.is_coinbase() { //coinbase tx don't have to be signed 
                    return Err(BlockchainError::InvalidTransactionSignature)
                }
            },
            None => {
                return Err(BlockchainError::InvalidTransactionSignature)
            }
        };

        let account = self.get_account(tx.get_sender())?;
        if !disable_nonce_check && account.nonce != *tx.get_nonce() {
            return Err(BlockchainError::InvalidTransactionNonce(account.nonce, *tx.get_nonce()))
        }

        match tx.get_data() {
            TransactionData::Normal(txs) => {
                if txs.len() == 0 {
                    return Err(BlockchainError::TxEmpty(hash.clone()))
                }
                let mut total_coins = *tx.get_fee();
                for output in txs {
                    total_coins += output.amount;
                    if output.to == *tx.get_sender() { //we can't transfer coins to ourself, why would you do that ?
                        return Err(BlockchainError::InvalidTransactionToSender(hash.clone()))
                    }

                    if !self.has_account(&output.to) { //verify that all receivers are registered
                        return Err(BlockchainError::AddressNotRegistered(output.to.clone()))
                    }
                }

                if account.balance < total_coins {
                    return Err(BlockchainError::NotEnoughFunds(tx.get_sender().clone(), total_coins))
                }
            }
            TransactionData::Burn(data) => {
                if account.balance < data.amount + tx.get_fee() {
                    return Err(BlockchainError::NotEnoughFunds(tx.get_sender().clone(), data.amount + tx.get_fee()))
                }
            }
            TransactionData::Coinbase(_) => {
                return Err(BlockchainError::CoinbaseTxNotAllowed(hash.clone()));
            }
            _ => {
                panic!("Not implemented yet")
            }
        };

        let fee = calculate_tx_fee(tx.size());
        if *tx.get_fee() < fee { //minimum fee verification
            return Err(BlockchainError::InvalidTxFee(fee, *tx.get_fee()))
        }

        Ok(())
    }

    fn execute_transaction(&mut self, transaction: &Transaction) -> Result<(), BlockchainError> {
        let mut amount = 0;
        match transaction.get_data() {
            TransactionData::Burn(tx) => {
                amount += tx.amount + transaction.get_fee();
                self.supply = self.supply - tx.amount; //by burning an amount, this amount can still be regenerated through block reward, should we prevent this ?
            }
            TransactionData::Normal(txs) => {
                let mut total = *transaction.get_fee();
                for tx in txs {
                    let to_account = self.get_mut_account(&tx.to)?;
                    to_account.balance += tx.amount;
                    total += tx.amount;
                }

                amount += total;
            }
            TransactionData::Registration => {
                self.register_account(transaction.get_sender());

                return Ok(())
            }
            TransactionData::Coinbase(tx) => {
                let account = self.get_mut_account(transaction.get_sender())?;
                account.balance += tx.amount;

                return Ok(())
            }
            _ => {
                panic!("not implemented")
            }
        };

        let account = self.get_mut_account(transaction.get_sender())?;
        account.balance -= amount;
        account.nonce += 1;

        Ok(())
    }
}

pub fn get_block_reward(supply: u64) -> u64 {
    let base_reward = (MAX_SUPPLY - supply) >> EMISSION_SPEED_FACTOR;
    base_reward
}

pub fn calculate_tx_fee(tx_size: usize) -> u64 {
    let mut size_in_kb = tx_size as u64 / 1024;

    if tx_size % 1024 != 0 { //we consume a full kb for fee
        size_in_kb += 1;
    }
    
    size_in_kb * FEE_PER_KB
}

use std::fmt::{Display, Error, Formatter};

impl Display for Blockchain {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "Blockchain[height: {}, top_hash: {}, accounts: {}, supply: {}]", self.height, self.top_hash, self.accounts.len(), self.supply)
    }
}

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        use BlockchainError::*;
        match self {
            AddressAlreadyRegistered(address) => write!(f, "Address {} is already registered", address.to_address().unwrap()),
            AddressNotRegistered(address) => write!(f, "Address {} is not registered", address.to_address().unwrap()),
            InvalidBlockHeight(expected, got) => write!(f, "Block height mismatch, expected {}, got {}", expected, got),
            InvalidBlockSize(expected, got) => write!(f, "Block size is more than limit: {}, got {}", expected, got),
            InvalidDifficulty(expected, got) => write!(f, "Invalid difficulty, expected {}, got {}", expected, got),
            InvalidHash(expected, got) => write!(f, "Invalid hash, expected {}, got {}", expected, got),
            InvalidPreviousBlockHash(expected, got) => write!(f, "Invalid previous block hash, expected {}, got {}", expected, got),
            InvalidTxFee(expected, got) => write!(f, "Invalid Tx fee, expected at least {}, got {}", expected, got),
            TimestampIsInFuture(timestamp, current) => write!(f, "Timestamp {} is greater than current time {}", timestamp, current),
            TimestampIsLessThanParent(timestamp) => write!(f, "Timestamp {} is less than parent", timestamp),
            TxNotFound(hash) => write!(f, "Tx {} not found in mempool", hash),
            TxAlreadyInMempool(hash) => write!(f, "Tx {} already in mempool", hash),
            TxEmpty(hash) => write!(f, "Normal Tx {} is empty", hash),
            DuplicateRegistration(address) => write!(f, "Duplicate registration tx for address '{}' found in same block", address.to_address().unwrap()),
            NotEnoughFunds(address, amount) => write!(f, "Address {} should have at least {}", address.to_address().unwrap(), amount),
            CoinbaseTxNotAllowed(hash) => write!(f, "Coinbase Tx not allowed: {}", hash),
            InvalidBlockReward(expected, got) => write!(f, "Invalid block reward, expected {}, got {}", expected, got),
            MultipleCoinbaseTx(value) => write!(f, "Incorrect amount of Coinbase TX in this block, expected 1, got {}", value),
            InvalidFeeReward(expected, got) => write!(f, "Invalid fee reward for this block, expected {}, got {}", expected, got),
            InvalidCirculatingSupply(expected, got) => write!(f, "Invalid circulating supply, expected {}, got {} coins generated!", expected, got),
            InvalidTxRegistrationPoW(hash) => write!(f, "Invalid tx registration PoW: {}", hash),
            InvalidTransactionNonce(expected, got) => write!(f, "Invalid transaction nonce: {}, account nonce is: {}", got, expected),
            InvalidTransactionToSender(hash) => write!(f, "Invalid transaction, sender trying to send coins to himself: {}", hash),
            ErrorOnBech32(e) => write!(f, "Error occured on bech32: {}", e),
            InvalidTransactionSignature => write!(f, "Invalid transaction signature"),
            DifficultyCannotBeZero => write!(f, "Difficulty cannot be zero!"),
            DifficultyErrorOnConversion => write!(f, "Difficulty error on conversion to BigUint"),
        }
    }
}