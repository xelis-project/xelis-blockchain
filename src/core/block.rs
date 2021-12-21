use crate::crypto::hash::{Hash, Hashable, hash};
use super::transaction::Transaction;
use super::serializer::Serializer;
use core::convert::TryInto;

const EXTRA_NONCE_SIZE: usize = 32;
const BLOCK_WORK_SIZE: usize = 160;

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

    pub fn get_txs_hash(&self) -> Hash {
        let mut bytes = vec![];

        for tx in &self.txs_hashes {
            bytes.extend(tx.as_bytes())
        }

        hash(&bytes)
    }

    pub fn get_txs_count(&self) -> usize {
        self.txs_hashes.len()
    }

    fn get_block_work(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        bytes.extend(&self.height.to_be_bytes()); // 8
        bytes.extend(&self.timestamp.to_be_bytes()); // 8 + 8 = 16
        bytes.extend(self.previous_hash.as_bytes()); // 16 + 32 = 48
        bytes.extend(&self.nonce.to_be_bytes()); // 48 + 8 = 56
        bytes.extend(&self.difficulty.to_be_bytes()); // 56 + 8 = 64
        bytes.extend(self.miner_tx.hash().as_bytes()); // 64 + 32 = 96
        bytes.extend(&self.extra_nonce); // 96 + 32 = 128
        bytes.extend(self.get_txs_hash().as_bytes()); // 128 + 32 = 160

        if bytes.len() != BLOCK_WORK_SIZE {
            panic!("Error, invalid block work size, got {} but expected {}", bytes.len(), BLOCK_WORK_SIZE)
        }

        bytes
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

    pub fn get_txs_count(&self) -> usize {
        self.transactions.len()
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
        bytes.extend(&self.difficulty.to_be_bytes()); // 56 + 8 = 64
        bytes.extend(&self.extra_nonce); // 64 + 32 = 96
        bytes.extend(self.get_txs_hash().as_bytes()); // 96 + 32 = 128
        bytes.extend(self.miner_tx.to_bytes()); // Dynamic

        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Option<(Box<Block>, usize)> {
        if bytes.len() < BLOCK_WORK_SIZE {
            return None
        }

        let mut n = 0;
        let height = u64::from_be_bytes(bytes[n..n+8].try_into().unwrap());
        n += 8;
        let timestamp = u64::from_be_bytes(bytes[n..n+8].try_into().unwrap());
        n += 8;
        let previous_hash = Hash::new(bytes[n..n+32].try_into().unwrap());
        n += 32;
        let nonce = u64::from_be_bytes(bytes[n..n+8].try_into().unwrap());
        n += 8;
        let difficulty = u64::from_be_bytes(bytes[n..n+8].try_into().unwrap());
        n += 8;
        let extra_nonce: [u8; 32] = bytes[n..n+32].try_into().unwrap();
        let (miner_tx, size) = Transaction::from_bytes(&bytes[n..])?; // n should be at 128
        n += size;
        let txs_count = u16::from_be_bytes(bytes[n..n+2].try_into().unwrap()) as usize;
        n += 2;
        if bytes.len() < (n + txs_count * 32)  {
            return None
        }
        n += 32 * txs_count;

        let mut txs_hashes = vec![];
        for _ in 0..txs_count {
            txs_hashes.push(Hash::new(bytes[n..n+32].try_into().unwrap()));
        }

        Some((Box::new(
            Block {
                difficulty,
                extra_nonce,
                height,
                timestamp,
                previous_hash,
                miner_tx: *miner_tx,
                nonce,
                txs_hashes
            }
        ), n))
    }
}

impl Hashable for Block {
    fn hash(&self) -> Hash {
        hash(&self.get_block_work())
    }
}

impl Serializer for CompleteBlock {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.block.to_bytes();
        for tx in &self.transactions {
            bytes.extend(tx.to_bytes());
        }
        bytes
    }

    fn from_bytes(buf: &[u8]) -> Option<(Box<CompleteBlock>, usize)> {
        let mut n = 0;
        let (block, read) = Block::from_bytes(&buf)?;
        n += read;
        let block: Block = *block;
        let mut txs: Vec<Transaction> = Vec::new();

        for _ in 0..block.get_txs_count() {
            let (tx, read) = Transaction::from_bytes(&buf[n..])?;
            txs.push(*tx);
            n += read;            
        }

        Some((Box::new(
            CompleteBlock::new(block, txs)
        ), n))
    }
}

impl Hashable for CompleteBlock {}

use std::fmt::{Error, Display, Formatter};

impl Display for CompleteBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "Block[height: {}, previous_hash: {}, timestamp: {}, nonce: {}, difficulty: {}, extra_nonce: {}, txs: {}]", self.block.height, self.block.previous_hash, self.block.timestamp, self.block.nonce, self.block.difficulty, hex::encode(self.block.extra_nonce), self.block.txs_hashes.len())
    }
}