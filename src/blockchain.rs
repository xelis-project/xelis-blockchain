use crate::globals::{Hash, Hashable, get_current_time};
use crate::block::Block;
use crate::difficulty::check_difficulty;
use crate::config::*;
use crate::transaction::*;
use std::collections::HashMap;

pub struct Blockchain {
    blocks: Vec<Block>,
    height: u64,
    top_hash: Hash,
    difficulty: u64,
    mempool: HashMap<Hash, Transaction>,
    accounts: HashMap<String, u64>
}

impl Blockchain {

    pub fn new() -> Self {
        Blockchain {
            blocks: vec![],
            height: 0,
            top_hash: [0; 32],
            difficulty: MINIMUM_DIFFICULTY,
            mempool: HashMap::new(),
            accounts: HashMap::new(),
        }
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

    pub fn get_block_template(&self) -> Block {
        let txs = self.mempool.values().cloned().collect();
        Block::new(self.height, get_current_time(), self.top_hash, self.difficulty, [0; 32], txs)
    }

    pub fn check_validity(&self) -> bool { //TODO use Result for error handling
        if self.height != self.blocks.len() as u64 {
            return false
        }

        for (height, block) in self.blocks.iter().enumerate() {
            if block.hash != block.hash() {
                println!("invalid block hash for {}", block);
                return false
            }

            if block.height != height as u64 {
                println!("Invalid block height for block {}, got {} but expected {}", block, block.height, height);
                return false
            }

            if block.height != 0 {
                let previous = &self.blocks[height - 1];
                
                if previous.hash != block.previous_hash {
                    println!("Invalid previous block hash, expected {} got {}", hex::encode(previous.hash), hex::encode(block.previous_hash));
                    return false;
                }
            }
        }

        true
    }

    pub fn add_new_block(&mut self, mut block: Block) { //TODO use Result for error handling
        let block_hash = block.hash();
        if self.height != block.height {
            panic!("Invalid block height, expected {} got {}", self.height, block.height);
        } else if block.size() > MAX_BLOCK_SIZE {
            panic!("Invalid block size, expected {} got {}", MAX_BLOCK_SIZE, block.size());
        } else if block.difficulty != self.difficulty {
            panic!("Invalid block difficulty, expected {} got {}", self.difficulty, block.difficulty);
        } else if !check_difficulty(&block_hash, block.difficulty) {
            panic!("Invalid hash for this block: {}", block);
        } else if block_hash != block.hash {
            panic!("Invalid block hash, got {} expected {}", hex::encode(block.hash), hex::encode(block_hash));
        }
        else if block.timestamp > get_current_time() {
            panic!("Invalid timestamp for this block: {}", block);
        }
        else if self.height != 0 {
            let previous_block = &self.blocks[(self.height as usize) - 1];
            if previous_block.hash != block.previous_hash {
                panic!("Invalid previous block hash, expected {} got {}", hex::encode(previous_block.hash), hex::encode(block.previous_hash))
            }
            if previous_block.timestamp > block.timestamp {
                panic!("Timestamp is less than previous block: {}", block);
            }

            for tx in &block.transactions {
                let tx = match self.mempool.remove(tx.get_hash()) {
                    Some(v) => v,
                    None => panic!("Tx {} not found", hex::encode(tx.get_hash()))
                };
    
                match &tx.get_data() {
                    TransactionData::Registration => {
                        if self.is_registered(tx.get_sender()) {
                            panic!("Address {} is already registered", tx.get_sender());
                        }
                    }
                    _ => {
                        if !self.is_registered(tx.get_sender()) {
                            panic!("Address {} is not registered!", tx.get_sender());
                        }
                    }
                };
                
    
                let hash = tx.hash();
                if *tx.get_hash() != hash {
                    panic!("Invalid Tx hash, expected {} got {}", hex::encode(hash), hex::encode(tx.get_hash()));
                }
            }

            println!("Block Time for this block is: {}s", block.timestamp - previous_block.timestamp);
        }

        for tx in &block.transactions {
            self.execute_transaction(&tx);
        }

        self.height = self.height + 1;
        self.top_hash = block_hash;
        println!("New block added to blockchain: {}", block);
        self.blocks.push(block);
    }

    fn execute_transaction(&mut self, transaction: &Transaction) { //TODO use Result for error handling
        match transaction.get_data() {
            TransactionData::Coinbase(tx) => {
                let balance = self.get_balance(transaction.get_sender()) + tx.reward;
                self.update_balance(transaction.get_sender(), balance);
            }
            TransactionData::Burn(tx) => {
                let balance = self.get_balance(transaction.get_sender());
                if *balance < tx.amount {
                    panic!("Not enough balance, expected at least {} but have {}", tx.amount, balance);
                }

                self.update_balance(transaction.get_sender(), balance - tx.amount);
            }
            TransactionData::Normal(tx) => {
                //TODO
            }
            TransactionData::Registration => {
                self.accounts.insert(transaction.get_sender().clone(), 0);
                println!("Account {} has been registered", transaction.get_sender());
            }
            TransactionData::SmartContract(tx) => {
                //TODO
            }
        }
    }
}
