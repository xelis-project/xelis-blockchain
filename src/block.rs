use crate::globals::get_current_time;
use crate::crypto::hash::{Hash, Hashable};
use crate::difficulty::check_difficulty;
use crate::transaction::Transaction;
use crate::blockchain::BlockchainError;

const EXTRA_NONCE_SIZE: usize = 32;

#[derive(serde::Serialize)]
pub struct Block {
    pub height: u64,
    pub timestamp: u64,
    pub previous_hash: Hash,
    pub nonce: u64,
    pub difficulty: u64,
    pub miner_tx: Transaction,
    #[serde(skip_serializing)]
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    pub txs_hashes: Vec<Hash> 
}

#[derive(serde::Serialize)]
pub struct CompleteBlock {
    hash: Hash, //hash of Block below
    #[serde(flatten)]
    block: Block,
    transactions: Vec<Transaction>
}

impl CompleteBlock {
    pub fn new(hash: Hash, block: Block, transactions: Vec<Transaction>) -> Self {
        CompleteBlock {
            hash,
            block,
            transactions
        }
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_height(&self) -> u64 {
        self.block.height
    }

    pub fn get_timestamp(&self) -> u64 {
        self.block.timestamp
    }

    pub fn get_previous_hash(&self) -> &Hash {
        &self.block.previous_hash
    }

    pub fn get_nonce(&self) -> u64 {
        self.block.nonce
    }

    pub fn get_difficulty(&self) -> u64 {
        self.block.difficulty
    }

    pub fn get_miner_tx(&self) -> &Transaction {
        &self.block.miner_tx
    }

    pub fn get_extra_nonce(&self) -> &[u8; EXTRA_NONCE_SIZE] {
        &self.block.extra_nonce
    }

    pub fn get_txs_hashes(&self) -> &Vec<Hash> {
        &self.block.txs_hashes
    }

    pub fn get_transactions(&self) -> &Vec<Transaction> {
        &self.transactions
    }
}

impl Block {
    pub fn new(height: u64, timestamp: u64, previous_hash: Hash, difficulty: u64, miner_tx: Transaction, txs_hashes: Vec<Hash>) -> Self {
        Block {
            height,
            timestamp,
            previous_hash,
            nonce: 0,
            difficulty,
            miner_tx,
            extra_nonce: [0; EXTRA_NONCE_SIZE],
            txs_hashes
        }
    }

    pub fn calculate_hash(&mut self) -> Result<Hash, BlockchainError> {
        loop {
            let hash = self.hash();
            if check_difficulty(&hash, self.difficulty)? {
                return Ok(hash)
            } else {
                self.nonce += 1;
                self.timestamp = get_current_time();
            }
        }
    }
}

impl Hashable for Block {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        bytes.extend(&self.height.to_be_bytes());
        bytes.extend(&self.timestamp.to_be_bytes());
        bytes.extend(self.previous_hash.as_bytes());
        bytes.extend(&self.nonce.to_be_bytes());
        bytes.extend(&self.difficulty.to_be_bytes());
        bytes.extend(&self.miner_tx.to_bytes());
        bytes.extend(&self.extra_nonce);

        bytes.extend(&self.txs_hashes.len().to_be_bytes());
        for hash in &self.txs_hashes {
            bytes.extend(hash.as_bytes());
        }

        bytes
    }
}

impl Hashable for CompleteBlock {
    fn to_bytes(&self) -> Vec<u8> {
        self.block.to_bytes()
    }
}

use std::fmt::{Error, Display, Formatter};

impl Display for CompleteBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "Block[height: {}, previous_hash: {}, hash: {}, timestamp: {}, nonce: {}, extra_nonce: {}, txs: {}]", self.block.height, self.block.previous_hash, self.hash, self.block.timestamp, self.block.nonce, hex::encode(self.block.extra_nonce), self.block.txs_hashes.len())
    }
}