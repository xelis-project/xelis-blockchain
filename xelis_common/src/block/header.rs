use std::{fmt::{Display, Formatter}, fmt::Error};
use indexmap::IndexSet;
use serde::Deserialize;
use log::debug;
use crate::{
    block::{BLOCK_WORK_SIZE, HEADER_WORK_SIZE},
    config::TIPS_LIMIT,
    crypto::{elgamal::CompressedPublicKey, hash, Hash, Hashable, HASH_SIZE},
    serializer::{Reader, ReaderError, Serializer, Writer},
    time::TimestampMillis
};
use super::EXTRA_NONCE_SIZE;

// Serialize the extra nonce in a hexadecimal string
pub fn serialize_extra_nonce<S: serde::Serializer>(extra_nonce: &[u8; EXTRA_NONCE_SIZE], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(extra_nonce))
}

// Deserialize the extra nonce from a hexadecimal string
pub fn deserialize_extra_nonce<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; EXTRA_NONCE_SIZE], D::Error> {
    let mut extra_nonce = [0u8; EXTRA_NONCE_SIZE];
    let hex = String::deserialize(deserializer)?;
    let decoded = hex::decode(hex).map_err(serde::de::Error::custom)?;
    extra_nonce.copy_from_slice(&decoded);
    Ok(extra_nonce)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BlockHeader {
    // Version of the block
    pub version: u8,
    // Merkle Hash containing merkle hash of all tips
    pub tips_merkle_hash: Hash,
    // Merkle Hash containing all balances changes of common base
    // A merkle hash of balances is based on previous topoheight merkle hash
    // and all changes of balances in the block
    pub balances_merkle_hash: Hash,
    // All TIPS of the block (previous hashes of the block)
    pub tips: IndexSet<Hash>,
    // Timestamp in milliseconds
    pub timestamp: TimestampMillis,
    // Height of the block
    pub height: u64,
    // Nonce of the block
    // This is the mutable part in mining process
    pub nonce: u64,
    // Extra nonce of the block
    // This is the mutable part in mining process
    // This is to spread even more the work in the network
    #[serde(serialize_with = "serialize_extra_nonce")]
    #[serde(deserialize_with = "deserialize_extra_nonce")]
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    // Miner public key
    pub miner: CompressedPublicKey,
    // All transactions hashes of the block
    pub txs_hashes: IndexSet<Hash>
}

impl BlockHeader {
    pub fn new(version: u8, tips_merkle_hash: Hash, balances_merkle_hash: Hash, height: u64, timestamp: TimestampMillis, tips: IndexSet<Hash>, extra_nonce: [u8; EXTRA_NONCE_SIZE], miner: CompressedPublicKey, txs_hashes: IndexSet<Hash>) -> Self {
        BlockHeader {
            version,
            tips_merkle_hash,
            balances_merkle_hash,
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

    pub fn set_miner(&mut self, key: CompressedPublicKey) {
        self.miner = key;
    }

    pub fn set_extra_nonce(&mut self, values: [u8; EXTRA_NONCE_SIZE]) {
        self.extra_nonce = values;
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn get_timestamp(&self) -> TimestampMillis {
        self.timestamp
    }

    pub fn get_tips(&self) -> &IndexSet<Hash> {
        &self.tips
    }

    // Compute a hash covering all tips hashes
    pub fn get_tips_hash(&self) -> Hash {
        let mut bytes = Vec::with_capacity(self.tips.len() * HASH_SIZE);

        for tx in &self.tips {
            bytes.extend(tx.as_bytes())
        }

        hash(&bytes)
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_miner(&self) -> &CompressedPublicKey {
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

    // Compute a hash covering all TXs hashes
    pub fn get_txs_hash(&self) -> Hash {
        let mut bytes = Vec::with_capacity(self.txs_hashes.len() * HASH_SIZE);
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
        bytes.extend(self.get_tips_merkle_hash().to_bytes()); // 1 + 32 = 33
        bytes.extend(self.get_balances_merkle_hash().to_bytes()); // 33 + 32 = 65
        bytes.extend(&self.height.to_be_bytes()); // 65 + 8 = 73
        bytes.extend(self.get_tips_hash().as_bytes()); // 73 + 32 = 105
        bytes.extend(self.get_txs_hash().as_bytes()); // 105 + 32 = 137 

        debug_assert!(bytes.len() == HEADER_WORK_SIZE, "Error, invalid header work size, got {} but expected {}", bytes.len(), HEADER_WORK_SIZE);

        bytes
    }

    // compute the header work hash (immutable part in mining process)
    pub fn get_work_hash(&self) -> Hash {
        hash(&self.get_work())
    }

    // Get the tips merkle hash of the block
    pub fn get_tips_merkle_hash(&self) -> &Hash {
        &self.tips_merkle_hash
    }

    // Get the balances merkle hash of the block
    pub fn get_balances_merkle_hash(&self) -> &Hash {
        &self.balances_merkle_hash
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

impl Serializer for BlockHeader {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.version); // 1
        writer.write_hash(&self.tips_merkle_hash); // 1 + 32 = 33
        writer.write_hash(&self.balances_merkle_hash); // 33 + 32 = 65 
        writer.write_u64(&self.height); // 65 + 8 = 73
        writer.write_u64(&self.timestamp); // 73 + 8 = 81
        writer.write_u64(&self.nonce); // 81 + 8 = 89
        writer.write_bytes(&self.extra_nonce); // 89 + 32 = 121
        writer.write_u8(self.tips.len() as u8); // 121 + 1 = 122
        for tip in &self.tips {
            writer.write_hash(tip); // 32
        }

        writer.write_u16(self.txs_hashes.len() as u16); // 122 + (N*32) + 2 = 124 + (N*32)
        for tx in &self.txs_hashes {
            writer.write_hash(tx); // 32
        }
        self.miner.write(writer); // 124 + (N*32) + (T*32) + 32 = 156 + (N*32) + (T*32)
        // Minimum size is 156 bytes
    }

    fn read(reader: &mut Reader) -> Result<BlockHeader, ReaderError> {
        let version = reader.read_u8()?;
        // At this moment we only support version 0, so we check it here directly
        if version != 0 {
            debug!("Expected version 0 got version {version}");
            return Err(ReaderError::InvalidValue)
        }

        let tips_merkle_hash = reader.read_hash()?;
        let balances_merkle_hash = reader.read_hash()?;
        let height = reader.read_u64()?;
        let timestamp = reader.read_u64()?;
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

        let miner = CompressedPublicKey::read(reader)?;
        Ok(
            BlockHeader {
                version,
                tips_merkle_hash,
                balances_merkle_hash,
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

    fn size(&self) -> usize {
        // additional byte for tips count
        let tips_size = 1 + self.tips.len() * HASH_SIZE;
        // 2 bytes for txs count (u16)
        let txs_size = 2 + self.txs_hashes.len() * HASH_SIZE;
        // Version is u8
        let version_size = 1;

        EXTRA_NONCE_SIZE + tips_size + txs_size + version_size
        + self.miner.size()
        + self.timestamp.size()
        + self.height.size()
        + self.nonce.size()
        + self.balances_merkle_hash.size()
    }
}

impl Hashable for BlockHeader {
    // this function has the same behavior as the get_pow_hash function
    // but we use a fast algorithm here
    fn hash(&self) -> Hash {
        hash(&self.get_serialized_header())
    }
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let mut tips = Vec::with_capacity(self.tips.len());
        for hash in &self.tips {
            tips.push(format!("{}", hash));
        }
        write!(f, "BlockHeader[height: {}, tips: [{}], timestamp: {}, nonce: {}, extra_nonce: {}, txs: {}]", self.height, tips.join(", "), self.timestamp, self.nonce, hex::encode(self.extra_nonce), self.txs_hashes.len())
    }
}