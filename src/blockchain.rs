use crate::globals::{Hash, Hashable, get_current_time};
use crate::block::Block;
use crate::difficulty::check_difficulty;
use crate::config::*;
use crate::transaction::*;
use std::collections::HashMap;

pub enum ErrorType {
    TimestampIsLessThanParent(u64),
    TimestampIsInFuture(u64, u64), //left is expected, right is got
    InvalidBlockHeight(u64, u64),
    InvalidDifficulty(u64, u64),
    InvalidHash(Hash, Hash),
    InvalidPreviousBlockHash(Hash, Hash),
    InvalidBlockSize(usize, usize),
    TxNotFound(Hash),
    InvalidTxFee(u64, u64),
    AddressNotRegistered(String),
    AddressAlreadyRegistered(String),
    NotEnoughFunds(String, u64),
    CoinbaseTxNotAllowed(Hash),
    MultipleCoinbaseTx(u64),
    InvalidBlockReward(u64, u64),
    InvalidFeeReward(u64, u64)
}

pub struct Blockchain {
    blocks: Vec<Block>,
    height: u64,
    supply: u64,
    top_hash: Hash,
    difficulty: u64,
    mempool: HashMap<Hash, Transaction>,
    accounts: HashMap<String, u64>,
    dev_address: String
}

impl Blockchain {

    pub fn new(dev_address: String) -> Self {
        let mut blockchain = Blockchain {
            blocks: vec![],
            height: 0,
            supply: 0,
            top_hash: [0; 32],
            difficulty: MINIMUM_DIFFICULTY,
            mempool: HashMap::new(),
            accounts: HashMap::new(),
            dev_address: dev_address.clone()
        };

        blockchain.accounts.insert(dev_address, 0);

        blockchain
    }

    pub fn get_current_height(&self) -> u64 {
        self.height
    }

    pub fn get_top_block_hash(&self) -> Hash {
        self.top_hash
    }

    pub fn get_top_block(&self) -> Option<&Block> {
        self.blocks.get(self.blocks.len() - 1)
    }

    pub fn get_difficulty(&self) -> u64 {
        self.difficulty
    }

    pub fn get_mempool(&self) -> &HashMap<Hash, Transaction> {
        &self.mempool
    }

    pub fn is_registered(&self, account: &String) -> bool {
        self.accounts.contains_key(account)
    }

    pub fn get_balance(&self, account: &String) -> &u64 {
        self.accounts.get(account).unwrap()
    }

    pub fn update_balance(&mut self, account: &String, amount: u64) {
        match self.accounts.get_mut(account) {
            Some(v) => *v = amount,
            None => panic!("This account is not registered!")
        };
    }

    pub fn has_enough_balance(&self, account: &String, amount: u64) -> bool {
        *self.accounts.get(account).unwrap() >= amount
    }

    //chicken & egg problem
    pub fn get_block_template(&self, address: String) -> Block {
        let block_reward = get_block_reward(self.supply); //TODO calculate fees
        let coinbase_tx = Transaction::new(self.height, TransactionData::Coinbase(CoinbaseTx {
            block_reward: block_reward,
            fee: 0
        }), address);

        let mut block = Block::new(self.height, get_current_time(), self.top_hash, self.difficulty, block_reward, [0; 32], vec![coinbase_tx]);
        
        let mut transactions: Vec<Transaction> = self.mempool.values().cloned().collect();
        transactions.sort_by(| a, b | a.get_fee().cmp(&b.get_fee())); //TODO

        let mut fee = 0;
        while transactions.len() > 0 && block.size() + transactions[0].size() < MAX_BLOCK_SIZE {
            let tx = transactions.remove(0);
            fee = fee + tx.get_fee();
            block.transactions.push(tx);
        }

        block
    }

    pub fn check_validity(&self) -> Result<(), ErrorType> {
        if self.height != self.blocks.len() as u64 {
            return Err(ErrorType::InvalidBlockHeight(self.height, self.blocks.len() as u64))
        }

        for (height, block) in self.blocks.iter().enumerate() {
            let hash = block.hash();
            if hash != block.hash {
                println!("invalid block hash for {}", block);
                return Err(ErrorType::InvalidHash(block.hash, hash))
            }

            if block.height != height as u64 {
                println!("Invalid block height for block {}, got {} but expected {}", block, block.height, height);
                return Err(ErrorType::InvalidBlockHeight(block.height, height as u64))
            }

            if block.height != 0 {
                let previous = &self.blocks[height - 1];
                
                if previous.hash != block.previous_hash {
                    println!("Invalid previous block hash, expected {} got {}", hex::encode(previous.hash), hex::encode(block.previous_hash));
                    return Err(ErrorType::InvalidHash(previous.hash, block.previous_hash));
                }
            }
        }

        Ok(())
    }

    pub fn add_new_block(&mut self, block: Block) -> Result<(), ErrorType> { //TODO use Result for error handling
        let block_hash = block.hash();
        if self.height != block.height {
            return Err(ErrorType::InvalidBlockHeight(block.height, block.height));
        } else if block.size() > MAX_BLOCK_SIZE {
            return Err(ErrorType::InvalidBlockSize(MAX_BLOCK_SIZE, block.size()));
        } else if !check_difficulty(&block_hash, block.difficulty) || block.difficulty != self.difficulty {
            return Err(ErrorType::InvalidDifficulty(self.difficulty, block.difficulty));
        } else if block_hash != block.hash {
            return Err(ErrorType::InvalidHash(block_hash, block.hash));
        }
        else if block.timestamp > get_current_time() {
            return Err(ErrorType::TimestampIsInFuture(get_current_time(), block.timestamp));
        }
        else if self.height != 0 {
            let previous_block = &self.blocks[(self.height as usize) - 1];
            if previous_block.hash != block.previous_hash {
                return Err(ErrorType::InvalidPreviousBlockHash(block.previous_hash, previous_block.hash));
            }
            if previous_block.timestamp > block.timestamp {
                return Err(ErrorType::TimestampIsLessThanParent(block.timestamp));
            }

            let block_reward = get_block_reward(self.supply);
            if block.reward != block_reward {
                return Err(ErrorType::InvalidBlockReward(block_reward, block.reward));
            }
            
            let mut coinbase_count = 0;
            let mut total_fee = 0;
            let mut fee_reward: u64 = 0;
            for tx in &block.transactions {
                if !self.mempool.contains_key(tx.get_hash()) && !tx.is_coinbase() {
                    return Err(ErrorType::TxNotFound(tx.get_hash().clone()));
                }

                match tx.get_data() {
                    TransactionData::Coinbase(data) => {
                        if !self.is_registered(tx.get_sender()) {
                            return Err(ErrorType::AddressNotRegistered(tx.get_sender().clone()));
                        }
        
                        if data.block_reward != block.reward {
                            return Err(ErrorType::InvalidBlockReward(block.reward, data.block_reward));
                        }

                        if *tx.get_fee() != 0 {
                            return Err(ErrorType::InvalidTxFee(0, *tx.get_fee()))
                        }

                        coinbase_count = coinbase_count + 1;
                        fee_reward = data.fee;
                    }
                    _ => {
                        if let Err(e) = self.verify_transaction(tx) {
                            return Err(e);
                        }
                        total_fee = total_fee + tx.get_fee();
                    }
                };
            }

            if coinbase_count != 1 {
                return Err(ErrorType::MultipleCoinbaseTx(coinbase_count));
            }

            if fee_reward != total_fee {
                return Err(ErrorType::InvalidFeeReward(total_fee, fee_reward));
            }

            println!("Block Time for this block is: {}s", block.timestamp - previous_block.timestamp);
        }

        for tx in &block.transactions {
            if let None = self.mempool.remove(tx.get_hash()) {
                if !tx.is_coinbase() {
                    panic!("Tx {} is not anymore in the mempool! Why ?", hex::encode(tx.get_hash()));
                }
            }
            self.execute_transaction(&tx);
        }

        self.height = self.height + 1;
        self.top_hash = block_hash;
        println!("New block added to blockchain: {}", block);
        if self.blocks.len() > 1 {
            let previous_block = &self.blocks[self.blocks.len() - 1];
            println!("Block time: {}s", (block.timestamp - previous_block.timestamp))
        }
        self.blocks.push(block);

        Ok(())
    }

    fn verify_transaction(&self, tx: &Transaction) -> Result<(), ErrorType> { //will be used by the mempool too
        match tx.get_data() {
            TransactionData::Registration => {
                if self.is_registered(tx.get_sender()) {
                    return Err(ErrorType::AddressAlreadyRegistered(tx.get_sender().clone()))
                }
            }
            TransactionData::Burn(data) => {
                if !self.is_registered(tx.get_sender()) {
                    return Err(ErrorType::AddressNotRegistered(tx.get_sender().clone()))
                }

                if !self.has_enough_balance(tx.get_sender(), data.amount) {
                    return Err(ErrorType::NotEnoughFunds(tx.get_sender().clone(), data.amount))
                }
            }
            TransactionData::Coinbase(_) => {
                return Err(ErrorType::CoinbaseTxNotAllowed(tx.get_hash().clone()));
            }
            _ => {
                if !self.is_registered(tx.get_sender()) {
                    return Err(ErrorType::AddressNotRegistered(tx.get_sender().clone()))
                }
            }
        };

        let fee = calculate_tx_fee(tx.size());
        if *tx.get_fee() < fee {
            return Err(ErrorType::InvalidTxFee(fee, *tx.get_fee()))
        }

        let hash = tx.hash();
        if *tx.get_hash() != hash {
            return Err(ErrorType::InvalidHash(hash, tx.get_hash().clone()));
        }

        Ok(())
    }

    fn execute_transaction(&mut self, transaction: &Transaction) {
        match transaction.get_data() {
            TransactionData::Burn(tx) => {
                let balance = *self.get_balance(transaction.get_sender());
                self.update_balance(transaction.get_sender(), balance - tx.amount);
                self.supply = self.supply - tx.amount;
            }
            TransactionData::Normal(_) => {
                //TODO
                panic!("not implemented")
            }
            TransactionData::Registration => {
                self.accounts.insert(transaction.get_sender().clone(), 0);
                println!("Account {} has been registered", transaction.get_sender());
            }
            TransactionData::SmartContract(_) => {
                //TODO
                panic!("not implemented")
            }
            TransactionData::Coinbase(tx) => {
                let balance = self.get_balance(transaction.get_sender()) + tx.block_reward + tx.fee;
                self.update_balance(transaction.get_sender(), balance);
                self.supply = self.supply + tx.block_reward;
            }
        }
    }
}

pub fn get_block_reward(supply: u64) -> u64 {
    let base_reward = (MAX_SUPPLY - supply) >> EMISSION_SPEED_FACTOR;
    base_reward
}

pub fn calculate_tx_fee(tx_size: usize) -> u64 {
    let mut size_in_kb = tx_size as u64 / 1024;

    if tx_size % 1024 != 0 { //we consume a full kb for fee
        size_in_kb = size_in_kb + 1;
    }
    
    size_in_kb * FEE_PER_KB
}

use std::fmt::{Display, Error, Formatter};

impl Display for Blockchain {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "Blockchain[height: {}, top_hash: {}, accounts: {}, supply: {}]", self.height, hex::encode(self.top_hash), self.accounts.len(), self.supply)
    }
}

impl Display for ErrorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self {
            ErrorType::AddressAlreadyRegistered(address) => write!(f, "Address {} is already registered", address),
            ErrorType::AddressNotRegistered(address) => write!(f, "Address {} is not registered", address),
            ErrorType::InvalidBlockHeight(expected, got) => write!(f, "Block height mismatch, expected {}, got {}", expected, got),
            ErrorType::InvalidBlockSize(expected, got) => write!(f, "Block size is more than limit: {}, got {}", expected, got),
            ErrorType::InvalidDifficulty(expected, got) => write!(f, "Invalid difficulty, expected {}, got {}", expected, got),
            ErrorType::InvalidHash(expected, got) => write!(f, "Invalid hash, expected {}, got {}", hex::encode(expected), hex::encode(got)),
            ErrorType::InvalidPreviousBlockHash(expected, got) => write!(f, "Invalid previous block hash, expected {}, got {}", hex::encode(expected), hex::encode(got)),
            ErrorType::InvalidTxFee(expected, got) => write!(f, "Invalid Tx fee, expected at least {}, got {}", expected, got),
            ErrorType::TimestampIsInFuture(timestamp, current) => write!(f, "Timestamp {} is greater than current time {}", timestamp, current),
            ErrorType::TimestampIsLessThanParent(timestamp) => write!(f, "Timestamp {} is less than parent", timestamp),
            ErrorType::TxNotFound(hash) => write!(f, "Tx {} not found", hex::encode(hash)),
            ErrorType::NotEnoughFunds(address, amount) => write!(f, "Address {} should have at least {}", address, amount),
            ErrorType::CoinbaseTxNotAllowed(hash) => write!(f, "Coinbase Tx not allowed: {}", hex::encode(hash)),
            ErrorType::InvalidBlockReward(expected, got) => write!(f, "Invalid block reward, expected {}, got {}", expected, got),
            ErrorType::MultipleCoinbaseTx(value) => write!(f, "Incorrect amount of Coinbase TX in this block, expected 1, got {}", value),
            ErrorType::InvalidFeeReward(expected, got) => write!(f, "Invalid fee reward for this block, expected {}, got {}", expected, got)
        }
    }
}