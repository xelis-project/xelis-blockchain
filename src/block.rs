use crate::globals::{Hash, Hashable, get_current_time};
use crate::difficulty::check_difficulty;
use crate::transaction::Transaction;
use crate::blockchain::BlockchainError;

#[derive(serde::Serialize)]
pub struct Block {
    pub height: u64,
    pub timestamp: u64,
    pub previous_hash: Hash,
    pub hash: Hash,
    pub nonce: u64,
    pub difficulty: u64,
    pub reward: u64,
    pub extra_nonce: [u8; 32],
    pub transactions: Vec<Transaction>, //TODO split Block into two structures: Block & CompleteBlock (include full TXs)
}

impl Block {
    pub fn new(height: u64, timestamp: u64, previous_hash: Hash, difficulty: u64, reward: u64, extra_nonce: [u8; 32], transactions: Vec<Transaction>) -> Self {
        Block {
            height,
            timestamp,
            previous_hash,
            hash: [0; 32],
            nonce: 0,
            difficulty,
            reward,
            extra_nonce,
            transactions,
        }
    }

    pub fn calculate_hash(&mut self) -> Result<(), BlockchainError> {
        loop {
            let hash = self.hash();
            if check_difficulty(&hash, self.difficulty)? {
                self.hash = hash;
                break;
            } else {
                self.nonce += 1;
                self.timestamp = get_current_time();
            }
        }

        Ok(())
    }
}

impl Hashable for Block {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        bytes.extend(&self.height.to_be_bytes());
        bytes.extend(&self.timestamp.to_be_bytes());
        bytes.extend(&self.previous_hash);
        bytes.extend(&self.nonce.to_be_bytes());
        bytes.extend(&self.difficulty.to_be_bytes());
        bytes.extend(&self.reward.to_be_bytes());
        bytes.extend(&self.extra_nonce);

        bytes.extend(&self.transactions.len().to_be_bytes());
        for tx in &self.transactions {
            bytes.extend(tx.to_bytes());
        }

        bytes
    }
}

use std::fmt::{Error, Display, Formatter};

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "Block[height: {}, timestamp: {}, previous_hash: {}, hash: {}, nonce: {}, reward: {}, extra_nonce: {}, txs: {}]", self.height, self.timestamp, hex::encode(self.previous_hash), hex::encode(self.hash), self.nonce, self.reward, hex::encode(self.extra_nonce), self.transactions.len())
    }
}