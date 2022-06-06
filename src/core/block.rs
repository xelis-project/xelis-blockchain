use crate::crypto::hash::{Hash, Hashable, hash};
use crate::crypto::key::PublicKey;
use super::transaction::Transaction;
use super::serializer::Serializer;
use super::reader::{Reader, ReaderError};
use super::writer::Writer;

const EXTRA_NONCE_SIZE: usize = 32;
const BLOCK_WORK_SIZE: usize = 160;

#[derive(serde::Serialize, Clone)]
pub struct Block {
    pub previous_hash: Hash,
    pub timestamp: u128,
    pub height: u64,
    pub nonce: u64,
    #[serde(skip_serializing)]
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    pub miner_tx: Transaction,
    pub txs_hashes: Vec<Hash>
}

#[derive(serde::Serialize, Clone)]
pub struct CompleteBlock {
    #[serde(flatten)]
    block: Block,
    difficulty: u64,
    transactions: Vec<Transaction>
}

impl Block {
    pub fn new(height: u64, timestamp: u128, previous_hash: Hash, extra_nonce: [u8; EXTRA_NONCE_SIZE], miner_tx: Transaction, txs_hashes: Vec<Hash>) -> Self {
        Block {
            height,
            timestamp,
            previous_hash,
            nonce: 0,
            extra_nonce,
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
        bytes.extend(&self.timestamp.to_be_bytes()); // 8 + 16 = 24
        bytes.extend(self.previous_hash.as_bytes()); // 24 + 32 = 56
        bytes.extend(&self.nonce.to_be_bytes()); // 56 + 8 = 64
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
    pub fn new(block: Block, difficulty: u64, transactions: Vec<Transaction>) -> Self {
        CompleteBlock {
            block,
            difficulty,
            transactions
        }
    }

    pub fn get_height(&self) -> u64 {
        self.block.height
    }

    pub fn get_difficulty(&self) -> u64 {
        self.difficulty
    }

    pub fn get_timestamp(&self) -> u128 {
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

    pub fn get_miner(&self) -> &PublicKey {
        &self.block.miner_tx.get_sender()
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
}

impl Serializer for Block {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.height); // 8
        writer.write_u128(&self.timestamp); // 8 + 16 = 24
        writer.write_hash(&self.previous_hash); // 24 + 32 = 56
        writer.write_u64(&self.nonce); // 56 + 8 = 64
        writer.write_bytes(&self.extra_nonce); // 64 + 32 = 96
        writer.write_u16(&(self.txs_hashes.len() as u16)); // 96 + 2 = 98
        for tx in &self.txs_hashes {
            writer.write_hash(tx);
        }
        self.miner_tx.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Block, ReaderError> {
        let height = reader.read_u64()?;
        let timestamp = reader.read_u128()?;
        let previous_hash = Hash::new(reader.read_bytes_32()?);
        let nonce = reader.read_u64()?;
        let extra_nonce: [u8; 32] = reader.read_bytes_32()?;
        let txs_count = reader.read_u16()?;
        let mut txs_hashes = vec![];
        for _ in 0..txs_count {
            txs_hashes.push(Hash::new(reader.read_bytes_32()?));
        }
        let miner_tx = Transaction::read(reader)?;

        Ok(
            Block {
                extra_nonce,
                height,
                timestamp,
                previous_hash,
                miner_tx,
                nonce,
                txs_hashes
            }
        )
    }
}

impl Hashable for Block {
    fn hash(&self) -> Hash {
        hash(&self.get_block_work())
    }
}

impl Serializer for CompleteBlock {
    fn write(&self, writer: &mut Writer) {
        self.block.write(writer);
        writer.write_u64(&self.difficulty);
        for tx in &self.transactions {
            tx.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<CompleteBlock, ReaderError> {
        let block = Block::read(reader)?;
        let difficulty = reader.read_u64()?;
        let mut txs: Vec<Transaction> = Vec::new();
        for _ in 0..block.get_txs_count() {
            let tx = Transaction::read(reader)?;
            txs.push(tx);     
        }

        Ok(CompleteBlock::new(block, difficulty, txs))
    }
}

impl Hashable for CompleteBlock {
    fn hash(&self) -> Hash {
        self.block.hash()
    }
}

use std::fmt::{Error, Display, Formatter};

impl Display for CompleteBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "Block[height: {}, previous_hash: {}, timestamp: {}, nonce: {}, extra_nonce: {}, txs: {}]", self.block.height, self.block.previous_hash, self.block.timestamp, self.block.nonce, hex::encode(self.block.extra_nonce), self.block.txs_hashes.len())
    }
}