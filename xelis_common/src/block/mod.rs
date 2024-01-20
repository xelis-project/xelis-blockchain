mod miner;

use indexmap::IndexSet;
use serde::Deserialize;
use log::debug;

use crate::{
    config::TIPS_LIMIT,
    crypto::{
        hash::{Hash, Hashable, hash},
        key::PublicKey,
    },
    immutable::Immutable,
    transaction::Transaction,
    serializer::{Serializer, Writer, Reader, ReaderError}
};
pub use miner::BlockMiner;

pub const EXTRA_NONCE_SIZE: usize = 32;
pub const HEADER_WORK_SIZE: usize = 73;
pub const BLOCK_WORK_SIZE: usize = 120; // 32 + 16 + 8 + 32 + 32 = 120

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

// transform it as u64, its good enough until serde is able to de/serialize u128
pub fn serialize_timestamp<S: serde::Serializer>(timestamp: &u128, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(*timestamp as u64)
}

pub fn deserialize_timestamp<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    Ok(u64::deserialize(deserializer)? as u128)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BlockHeader {
    pub version: u8,
    pub tips: IndexSet<Hash>,
    #[serde(serialize_with = "serialize_timestamp")]
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub timestamp: u128,
    pub height: u64,
    pub nonce: u64,
    #[serde(serialize_with = "serialize_extra_nonce")]
    #[serde(deserialize_with = "deserialize_extra_nonce")]
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    pub miner: PublicKey,
    pub txs_hashes: IndexSet<Hash>
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Block {
    #[serde(flatten)]
    header: Immutable<BlockHeader>,
    transactions: Vec<Immutable<Transaction>>
}

impl BlockHeader {
    pub fn new(version: u8, height: u64, timestamp: u128, tips: IndexSet<Hash>, extra_nonce: [u8; EXTRA_NONCE_SIZE], miner: PublicKey, txs_hashes: IndexSet<Hash>) -> Self {
        BlockHeader {
            version,
            height,
            timestamp,
            tips,
            nonce: 0,
            extra_nonce,
            miner,
            txs_hashes
        }
    }

    pub fn get_version(&self) -> u8 {
        self.version
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

    pub fn get_tips(&self) -> &IndexSet<Hash> {
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

    pub fn get_txs_hashes(&self) -> &IndexSet<Hash> {
        &self.txs_hashes
    }

    pub fn take_txs_hashes(self) -> IndexSet<Hash> {
        self.txs_hashes
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

    // Build the header work (immutable part in mining process)
    // This is the part that will be used to compute the header work hash
    // See get_work_hash function and get_serialized_header for final hash computation
    pub fn get_work(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(HEADER_WORK_SIZE);

        bytes.push(self.version); // 1
        bytes.extend(&self.height.to_be_bytes()); // 1 + 8 = 9
        bytes.extend(self.get_tips_hash().as_bytes()); // 9 + 32 = 41
        bytes.extend(self.get_txs_hash().as_bytes()); // 41 + 32 = 73

        debug_assert!(bytes.len() == HEADER_WORK_SIZE, "Error, invalid header work size, got {} but expected {}", bytes.len(), HEADER_WORK_SIZE);

        bytes
    }

    // compute the header work hash (immutable part in mining process)
    pub fn get_work_hash(&self) -> Hash {
        hash(&self.get_work())
    }

    // This is similar as BlockMiner work
    fn get_serialized_header(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BLOCK_WORK_SIZE);
        bytes.extend(self.get_work_hash().to_bytes());
        bytes.extend(self.timestamp.to_be_bytes());
        bytes.extend(self.nonce.to_be_bytes());
        bytes.extend(self.extra_nonce);
        bytes.extend(self.miner.as_bytes());

        debug_assert!(bytes.len() == BLOCK_WORK_SIZE, "invalid block work size, got {} but expected {}", bytes.len(), BLOCK_WORK_SIZE);

        bytes
    }

    // compute the block POW hash
    pub fn get_pow_hash(&self) -> Hash {
        // TODO replace with the real POW algorithm
        hash(&self.get_serialized_header())
    }

    pub fn get_transactions(&self) -> &IndexSet<Hash> {
        &self.txs_hashes
    }
}

impl Block {
    pub fn new(block: Immutable<BlockHeader>, transactions: Vec<Immutable<Transaction>>) -> Self {
        Block {
            header: block,
            transactions
        }
    }

    pub fn with(mut block: BlockHeader, transactions: Vec<Transaction>) -> Self {
        transactions.iter().for_each(|tx| {
            block.txs_hashes.insert(tx.hash());
        });

        Block {
            header: Immutable::Owned(block),
            transactions: transactions.into_iter().map(|tx| Immutable::Owned(tx)).collect()
        }
    }

    pub fn to_header(self) -> Arc<BlockHeader> {
        self.header.to_arc()
    }

    pub fn get_header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn get_txs_count(&self) -> usize {
        self.transactions.len()
    }

    pub fn get_transactions(&self) -> &Vec<Immutable<Transaction>> {
        &self.transactions
    }

    pub fn split(self) -> (Immutable<BlockHeader>, Vec<Immutable<Transaction>>) {
        (self.header, self.transactions)
    }
}

impl Serializer for BlockHeader {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.version); // 1
        writer.write_u64(&self.height); // 1 + 8 = 9
        writer.write_u128(&self.timestamp); // 9 + 16 = 25
        writer.write_u64(&self.nonce); // 25 + 8 = 33
        writer.write_bytes(&self.extra_nonce); // 33 + 32 = 65
        writer.write_u8(self.tips.len() as u8); // 65 + 1 = 66
        for tip in &self.tips {
            writer.write_hash(tip); // 32
        }

        writer.write_u16(self.txs_hashes.len() as u16); // 66 + 2 = 68
        for tx in &self.txs_hashes {
            writer.write_hash(tx); // 32
        }
        self.miner.write(writer); // 68 + 32 = 100
    }

    fn read(reader: &mut Reader) -> Result<BlockHeader, ReaderError> {
        let version = reader.read_u8()?;
        let height = reader.read_u64()?;
        let timestamp = reader.read_u128()?;
        let nonce = reader.read_u64()?;
        let extra_nonce: [u8; 32] = reader.read_bytes_32()?;

        let tips_count = reader.read_u8()?;
        if tips_count as usize > TIPS_LIMIT {
            debug!("Error, too many tips in block header");
            return Err(ReaderError::InvalidValue)
        }
        
        let mut tips = IndexSet::with_capacity(tips_count as usize);
        for _ in 0..tips_count {
            if !tips.insert(reader.read_hash()?) {
                debug!("Error, duplicate tip found in block header");
                return Err(ReaderError::InvalidValue)
            }
        }

        let txs_count = reader.read_u16()?;
        let mut txs_hashes = IndexSet::with_capacity(txs_count as usize);
        for _ in 0..txs_count {
            if !txs_hashes.insert(reader.read_hash()?) {
                debug!("Error, duplicate tx hash found in block header");
                return Err(ReaderError::InvalidValue)
            }
        }

        let miner = PublicKey::read(reader)?;
        Ok(
            BlockHeader {
                version,
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
    // this function has the same behavior as the get_pow_hash function
    // but we use a fast algorithm here
    fn hash(&self) -> Hash {
        hash(&self.get_serialized_header())
    }
}

impl Serializer for Block {
    fn write(&self, writer: &mut Writer) {
        self.header.write(writer);
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
        self.header.hash()
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