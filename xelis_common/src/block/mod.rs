use serde::Deserialize;

use crate::crypto::hash::{Hash, Hashable, hash};
use crate::crypto::key::PublicKey;
use crate::immutable::Immutable;
use crate::transaction::Transaction;
use crate::serializer::{Serializer, Writer, Reader, ReaderError};

pub const EXTRA_NONCE_SIZE: usize = 32;
pub const BLOCK_WORK_SIZE: usize = 160;

pub fn serialize_extra_nonce<S: serde::Serializer>(extra_nonce: &[u8; EXTRA_NONCE_SIZE], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(extra_nonce))
}

pub fn deserialize_extra_nonce<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; EXTRA_NONCE_SIZE], D::Error> {
    let mut extra_nonce = [0u8; EXTRA_NONCE_SIZE];
    let hex = String::deserialize(deserializer)?;
    let decoded = hex::decode(hex).map_err(serde::de::Error::custom)?;
    extra_nonce.copy_from_slice(&decoded);
    Ok(extra_nonce)
}

// TODO fix deserializer
pub fn deserialize_timestamp<'de, D: serde::Deserializer<'de>>(_: D) -> Result<u128, D::Error> {
    Ok(0)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BlockHeader {
    pub tips: Vec<Hash>,
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub timestamp: u128,
    pub height: u64,
    pub nonce: u64,
    #[serde(serialize_with = "serialize_extra_nonce")]
    #[serde(deserialize_with = "deserialize_extra_nonce")]
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    pub miner: PublicKey,
    pub txs_hashes: Vec<Hash>
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Block {
    #[serde(flatten)]
    block: Immutable<BlockHeader>,
    transactions: Vec<Immutable<Transaction>>
}

impl BlockHeader {
    pub fn new(height: u64, timestamp: u128, tips: Vec<Hash>, extra_nonce: [u8; EXTRA_NONCE_SIZE], miner: PublicKey, txs_hashes: Vec<Hash>) -> Self {
        BlockHeader {
            height,
            timestamp,
            tips,
            nonce: 0,
            extra_nonce,
            miner,
            txs_hashes
        }
    }

    pub fn set_miner(&mut self, key: PublicKey) {
        self.miner = key;
    }

    pub fn set_extra_nonce(&mut self, values: [u8; EXTRA_NONCE_SIZE]) {
        self.extra_nonce = values;
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn get_timestamp(&self) -> u128 {
        self.timestamp
    }

    pub fn get_tips(&self) -> &Vec<Hash> {
        &self.tips
    }

    pub fn get_tips_hash(&self) -> Hash {
        let mut bytes = vec![];

        for tx in &self.tips {
            bytes.extend(tx.as_bytes())
        }

        hash(&bytes)
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_miner(&self) -> &PublicKey {
        &self.miner
    }

    pub fn get_extra_nonce(&self) -> &[u8; EXTRA_NONCE_SIZE] {
        &self.extra_nonce
    }

    pub fn get_txs_hashes(&self) -> &Vec<Hash> {
        &self.txs_hashes
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
        let mut bytes: Vec<u8> = Vec::with_capacity(BLOCK_WORK_SIZE);

        bytes.extend(&self.height.to_be_bytes()); // 8
        bytes.extend(&self.timestamp.to_be_bytes()); // 8 + 16 = 24
        bytes.extend(self.get_tips_hash().as_bytes()); // 24 + 32 = 56
        bytes.extend(&self.nonce.to_be_bytes()); // 56 + 8 = 64
        bytes.extend(self.miner.as_bytes()); // 64 + 32 = 96
        bytes.extend(&self.extra_nonce); // 96 + 32 = 128
        bytes.extend(self.get_txs_hash().as_bytes()); // 128 + 32 = 160

        if bytes.len() != BLOCK_WORK_SIZE {
            panic!("Error, invalid block work size, got {} but expected {}", bytes.len(), BLOCK_WORK_SIZE)
        }

        bytes
    }

    pub fn get_transactions(&self) -> &Vec<Hash> {
        &self.txs_hashes
    }
}

impl Block {
    pub fn new(block: Immutable<BlockHeader>, transactions: Vec<Immutable<Transaction>>) -> Self {
        Block {
            block,
            transactions
        }
    }

    pub fn to_header(self) -> Arc<BlockHeader> {
        self.block.to_arc()
    }

    pub fn get_header(&self) -> &BlockHeader {
        &self.block
    }

    pub fn get_txs_count(&self) -> usize {
        self.transactions.len()
    }

    pub fn get_transactions(&self) -> &Vec<Immutable<Transaction>> {
        &self.transactions
    }

    pub fn split(self) -> (Immutable<BlockHeader>, Vec<Immutable<Transaction>>) {
        (self.block, self.transactions)
    }
}

impl Serializer for BlockHeader {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.height); // 8
        writer.write_u128(&self.timestamp); // 8 + 16 = 24
        writer.write_u64(&self.nonce); // 24 + 8 = 32
        writer.write_bytes(&self.extra_nonce); // 32 + 32 = 64
        writer.write_u8(self.tips.len() as u8); // 64 + 1 = 65
        for tip in &self.tips {
            writer.write_hash(tip); // 32
        }

        writer.write_u16(self.txs_hashes.len() as u16); // 65 + 2 = 67
        for tx in &self.txs_hashes {
            writer.write_hash(tx); // 32
        }
        self.miner.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<BlockHeader, ReaderError> {
        let height = reader.read_u64()?;
        let timestamp = reader.read_u128()?;
        let nonce = reader.read_u64()?;
        let extra_nonce: [u8; 32] = reader.read_bytes_32()?;

        let tips_count = reader.read_u8()?;
        let mut tips = Vec::with_capacity(tips_count as usize);
        for _ in 0..tips_count {
            tips.push(reader.read_hash()?);
        }

        let txs_count = reader.read_u16()?;
        let mut txs_hashes = Vec::with_capacity(txs_count as usize);
        for _ in 0..txs_count {
            txs_hashes.push(reader.read_hash()?);
        }

        let miner = PublicKey::read(reader)?;
        Ok(
            BlockHeader {
                extra_nonce,
                height,
                timestamp,
                tips,
                miner,
                nonce,
                txs_hashes
            }
        )
    }
}

impl Hashable for BlockHeader {
    fn hash(&self) -> Hash {
        hash(&self.get_block_work())
    }
}

impl Serializer for Block {
    fn write(&self, writer: &mut Writer) {
        self.block.write(writer);
        for tx in &self.transactions {
            tx.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Block, ReaderError> {
        let block = BlockHeader::read(reader)?;
        let mut txs: Vec<Immutable<Transaction>> = Vec::new();
        for _ in 0..block.get_txs_count() {
            let tx = Transaction::read(reader)?;
            txs.push(Immutable::Owned(tx));     
        }

        Ok(Block::new(Immutable::Owned(block), txs))
    }
}

impl Hashable for Block {
    fn hash(&self) -> Hash {
        self.block.hash()
    }
}

impl Deref for Block {
    type Target = BlockHeader;

    fn deref(&self) -> &Self::Target {
        &self.get_header()        
    }
}

use std::fmt::{Error, Display, Formatter};
use std::ops::Deref;
use std::sync::Arc;

impl Display for BlockHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let mut tips = Vec::with_capacity(self.tips.len());
        for hash in &self.tips {
            tips.push(format!("{}", hash));
        }
        write!(f, "BlockHeader[height: {}, tips: [{}], timestamp: {}, nonce: {}, extra_nonce: {}, txs: {}]", self.height, tips.join(", "), self.timestamp, self.nonce, hex::encode(self.extra_nonce), self.txs_hashes.len())
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let mut tips = Vec::with_capacity(self.tips.len());
        for hash in &self.tips {
            tips.push(format!("{}", hash));
        }
        write!(f, "Block[height: {}, tips: [{}], timestamp: {}, nonce: {}, extra_nonce: {}, txs: {}]", self.height, tips.join(", "), self.timestamp, self.nonce, hex::encode(self.extra_nonce), self.txs_hashes.len())
    }
}