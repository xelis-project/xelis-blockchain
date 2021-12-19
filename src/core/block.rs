use crate::crypto::hash::{Hash, Hashable};
use super::transaction::Transaction;
use super::serializer::Serializer;

const EXTRA_NONCE_SIZE: usize = 32;
const BLOCK_WORK_SIZE: usize = 152;

#[derive(serde::Serialize)]
pub struct Block {
    pub previous_hash: Hash,
    pub timestamp: u64,
    pub height: u64,
    pub nonce: u64,
    pub difficulty: u64,
    #[serde(skip_serializing)]
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    pub miner_tx: Transaction,
    pub txs_hashes: Vec<Hash>
}

#[derive(serde::Serialize)]
pub struct CompleteBlock {
    #[serde(flatten)]
    block: Block,
    transactions: Vec<Transaction>
}

impl Block {
    pub fn new(height: u64, timestamp: u64, previous_hash: Hash, difficulty: u64, miner_tx: Transaction, txs_hashes: Vec<Hash>) -> Self {
        Block {
            height,
            timestamp,
            previous_hash,
            nonce: 0,
            difficulty,
            extra_nonce: [0; EXTRA_NONCE_SIZE],
            miner_tx,
            txs_hashes
        }
    }

    /*pub fn deserialize(bytes: &[u8]) -> Result<(), BlockchainError> {
        let mut buf_8: [u8; 8]; 
        buf_8.copy_from_slice(&bytes[0..8]);
        let height = u64::from_be_bytes(buf_8);

        buf_8.copy_from_slice(&bytes[8..8+8]);
        let timestamp = u64::from_be_bytes(buf_8);


        let mut buf_32: [u8; 32];
        buf_32.copy_from_slice(&bytes[16..16+32]);
        let previous_hash = Hash::new(buf_32);


        buf_8.copy_from_slice(&bytes[32..32+8]);
        let nonce = u64::from_be_bytes(buf_8);


        //bytes.extend(&self.miner_tx.to_bytes());
        buf_32.copy_from_slice(&bytes[40..40+32]);
        let extra_nonce = buf_32;

        bytes.extend(self.get_txs_hash().as_bytes());

        Ok(())
    }*/

    pub fn get_txs_hash(&self) -> Hash {
        let mut bytes = vec![];

        for tx in &self.txs_hashes {
            bytes.extend(tx.as_bytes())
        }

        crate::crypto::hash::hash(&bytes)
    }
}

impl CompleteBlock {
    pub fn new(block: Block, transactions: Vec<Transaction>) -> Self {
        CompleteBlock {
            block,
            transactions
        }
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

    pub fn get_difficulty(&self) -> u64 {
        self.block.difficulty
    }
}

impl Serializer for Block {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        bytes.extend(&self.height.to_be_bytes()); // 8
        bytes.extend(&self.timestamp.to_be_bytes()); // 8 + 8 = 16
        bytes.extend(self.previous_hash.as_bytes()); // 16 + 32 = 48
        bytes.extend(&self.nonce.to_be_bytes()); // 48 + 8 = 56
        bytes.extend(self.miner_tx.hash().as_bytes()); // 56 + 32 = 88
        bytes.extend(&self.extra_nonce); // 88 + 32 = 120
        bytes.extend(self.get_txs_hash().as_bytes()); // 120 + 32 = 152

        if bytes.len() != BLOCK_WORK_SIZE {
            panic!("Error, invalid block work size, got {} but expected {}", bytes.len(), BLOCK_WORK_SIZE)
        }

        bytes
    }

    fn from_bytes(buf: &[u8]) -> Option<Box<Block>> {
        None // TODO
    }
}

impl Hashable for Block {}

impl Serializer for CompleteBlock {
    fn to_bytes(&self) -> Vec<u8> {
        self.block.to_bytes()
    }

    fn from_bytes(buf: &[u8]) -> Option<Box<CompleteBlock>> {
        None // TODO
    }
}

impl Hashable for CompleteBlock {}

use std::fmt::{Error, Display, Formatter};

impl Display for CompleteBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "Block[height: {}, previous_hash: {}, timestamp: {}, nonce: {}, difficulty: {}, extra_nonce: {}, txs: {}]", self.block.height, self.block.previous_hash, self.block.timestamp, self.block.nonce, self.block.difficulty, hex::encode(self.block.extra_nonce), self.block.txs_hashes.len())
    }
}