use std::{fmt::{Display, Formatter}, fmt::Error};
use indexmap::IndexSet;
use serde::Deserialize;
use log::debug;
use crate::{
    block::{BLOCK_WORK_SIZE, HEADER_WORK_SIZE, BlockVersion},
    config::TIPS_LIMIT,
    crypto::{
        elgamal::{
            CompressedPublicKey,
            RISTRETTO_COMPRESSED_SIZE
        },
        hash,
        pow_hash,
        Hash,
        Hashable,
        HASH_SIZE
    },
    serializer::{Reader, ReaderError, Serializer, Writer},
    time::TimestampMillis,
    immutable::Immutable
};
use xelis_hash::Error as XelisHashError;
use super::{Algorithm, MinerWork, EXTRA_NONCE_SIZE};

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
    pub version: BlockVersion,
    // All TIPS of the block (previous hashes of the block)
    pub tips: Immutable<IndexSet<Hash>>,
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
    #[inline]
    pub fn new(version: BlockVersion, height: u64, timestamp: TimestampMillis, tips: impl Into<Immutable<IndexSet<Hash>>>, extra_nonce: [u8; EXTRA_NONCE_SIZE], miner: CompressedPublicKey, txs_hashes: IndexSet<Hash>) -> Self {
        Self {
            version,
            height,
            timestamp,
            tips: tips.into(),
            nonce: 0,
            extra_nonce,
            miner,
            txs_hashes
        }
    }

    // Apply a MinerWork to this block header to match the POW hash
    pub fn apply_miner_work(&mut self, work: MinerWork) -> bool {
        let (_, timestamp, nonce, miner, extra_nonce) = work.take();
        let Some(miner) = miner else {
            return false
        };

        self.miner = miner.into_owned();
        self.timestamp = timestamp;
        self.nonce = nonce;
        self.extra_nonce = extra_nonce;

        true
    }

    #[inline]
    pub fn get_version(&self) -> BlockVersion {
        self.version
    }

    #[inline]
    pub fn set_miner(&mut self, key: CompressedPublicKey) {
        self.miner = key;
    }

    #[inline]
    pub fn set_extra_nonce(&mut self, values: [u8; EXTRA_NONCE_SIZE]) {
        self.extra_nonce = values;
    }

    #[inline]
    pub fn get_height(&self) -> u64 {
        self.height
    }

    #[inline]
    pub fn get_timestamp(&self) -> TimestampMillis {
        self.timestamp
    }

    #[inline]
    pub fn get_tips(&self) -> &IndexSet<Hash> {
        &self.tips
    }

    #[inline]
    pub fn get_tips_count(&self) -> usize {
        self.tips.len()
    }

    #[inline]
    pub fn get_immutable_tips(&self) -> &Immutable<IndexSet<Hash>> {
        &self.tips
    }

    // Compute a hash covering all tips hashes
    pub fn get_tips_hash(&self) -> Hash {
        let mut bytes = Vec::with_capacity(self.tips.len() * HASH_SIZE);

        for tx in self.tips.iter() {
            bytes.extend(tx.as_bytes())
        }

        hash(&bytes)
    }

    #[inline]
    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    #[inline]
    pub fn get_miner(&self) -> &CompressedPublicKey {
        &self.miner
    }

    #[inline]
    pub fn get_extra_nonce(&self) -> &[u8; EXTRA_NONCE_SIZE] {
        &self.extra_nonce
    }

    #[inline]
    pub fn get_txs_hashes(&self) -> &IndexSet<Hash> {
        &self.txs_hashes
    }

    #[inline]
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

    #[inline]
    pub fn get_txs_count(&self) -> usize {
        self.txs_hashes.len()
    }

    // Build the header work (immutable part in mining process)
    // This is the part that will be used to compute the header work hash
    // See get_work_hash function and get_serialized_header for final hash computation
    pub fn get_work(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(HEADER_WORK_SIZE);

        bytes.extend(self.version.to_bytes()); // 1
        bytes.extend(&self.height.to_be_bytes()); // 1 + 8 = 9
        bytes.extend(self.get_tips_hash().as_bytes()); // 9 + 32 = 41
        bytes.extend(self.get_txs_hash().as_bytes()); // 41 + 32 = 73

        debug_assert!(bytes.len() == HEADER_WORK_SIZE, "Error, invalid header work size, got {} but expected {}", bytes.len(), HEADER_WORK_SIZE);

        bytes
    }

    // compute the header work hash (immutable part in mining process)
    #[inline]
    pub fn get_work_hash(&self) -> Hash {
        hash(&self.get_work())
    }

    // This is similar to MinerWork
    pub fn get_pow_challenge(&self) -> Vec<u8> {
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
    #[inline]
    pub fn get_pow_hash(&self, algorithm: Algorithm) -> Result<Hash, XelisHashError> {
        pow_hash(&self.get_pow_challenge(), algorithm)
    }

    #[inline]
    pub fn get_transactions(&self) -> &IndexSet<Hash> {
        &self.txs_hashes
    }

    pub fn estimate_size(tips_len: usize) -> usize {
        // additional byte for tips count
        let tips_size = 1 + tips_len * HASH_SIZE;
        // 2 bytes for txs count (u16)
        let txs_size = 2;
        // Version is u8
        let version_size = 1;

        EXTRA_NONCE_SIZE
        + tips_size
        + txs_size
        + version_size
        + RISTRETTO_COMPRESSED_SIZE // miner key
        + 8 // timestamp
        + 8 // height
        + 8 // nonce
    }
}

impl Serializer for BlockHeader {
    fn write(&self, writer: &mut Writer) {
        self.version.write(writer); // 1
        self.height.write(writer); // 1 + 8 = 9
        self.timestamp.write(writer); // 9 + 8 = 17
        self.nonce.write(writer); // 17 + 8 = 25
        writer.write_bytes(&self.extra_nonce); // 25 + 32 = 57
        writer.write_u8(self.tips.len() as u8); // 57 + 1 = 58
        for tip in self.tips.iter() {
            writer.write_hash(tip); // 32 per hash
        }

        writer.write_u16(self.txs_hashes.len() as u16); // 58 + (N*32) + 2 = 60 + (N*32)
        for tx in &self.txs_hashes {
            writer.write_hash(tx); // 32
        }
        self.miner.write(writer); // 60 + (N*32) + (T*32) + 32 = 92 + (N*32) + (T*32)
        // Minimum size is 92 bytes
    }

    fn read(reader: &mut Reader) -> Result<BlockHeader, ReaderError> {
        let version = BlockVersion::read(reader)?;
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
                extra_nonce,
                height,
                timestamp,
                tips: Immutable::Owned(tips),
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
    }
}

impl Hashable for BlockHeader {
    // this function has the same behavior as the get_pow_hash function
    // but we use a fast algorithm here
    fn hash(&self) -> Hash {
        hash(&self.get_pow_challenge())
    }
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let mut tips = Vec::with_capacity(self.tips.len());
        for hash in self.tips.iter() {
            tips.push(format!("{}", hash));
        }
        write!(f, "BlockHeader[height: {}, tips: [{}], timestamp: {}, nonce: {}, extra_nonce: {}, txs: {}]", self.height, tips.join(", "), self.timestamp, self.nonce, hex::encode(self.extra_nonce), self.txs_hashes.len())
    }
}

#[cfg(test)]
mod tests {
    use indexmap::IndexSet;
    use crate::{block::BlockVersion, crypto::{Hash, Hashable, KeyPair}, serializer::Serializer};
    use super::BlockHeader;

    #[test]
    fn test_block_template() {
        let mut tips = IndexSet::new();
        tips.insert(Hash::zero());

        let miner = KeyPair::new().get_public_key().compress();
        let header = BlockHeader::new(BlockVersion::V0, 0, 0, tips, [0u8; 32], miner, IndexSet::new());

        let serialized = header.to_bytes();
        assert!(serialized.len() == header.size());

        let deserialized = BlockHeader::from_bytes(&serialized).unwrap();
        assert!(header.hash() == deserialized.hash());
    }

    #[test]
    fn test_block_template_from_hex() {
        let serialized = "00000000000000002d0000018f1cbd697000000000000000000eded85557e887b45989a727b6786e1bd250de65042d9381822fa73d01d2c4ff01d3a0154853dbb01dc28c9102e9d94bea355b8ee0d82c3e078ac80841445e86520000d67ad13934337b85c34985491c437386c95de0d97017131088724cfbedebdc55";
        let header = BlockHeader::from_hex(serialized).unwrap();
        assert!(header.to_hex() == serialized);
    }
}