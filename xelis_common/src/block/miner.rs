use std::borrow::Cow;
use crate::{
    crypto::{
        PublicKey,
        Hashable,
        Hash,
        hash,
    },
    serializer::{Serializer, Writer, Reader, ReaderError},
    time::TimestampMillis,
};

use super::{EXTRA_NONCE_SIZE, BLOCK_WORK_SIZE};

// This structure is used by xelis-miner which allow to compute a valid block POW hash
#[derive(Clone, Debug)]
pub struct BlockMiner<'a> {
    header_work_hash: Hash, // include merkle tree of tips, txs, and height (immutable)
    timestamp: TimestampMillis, // miners can update timestamp to keep it up-to-date
    nonce: u64,
    miner: Option<Cow<'a, PublicKey>>,
    // Extra nonce so miner can write anything
    // Can also be used to spread more the work job and increase its work capacity
    extra_nonce: [u8; EXTRA_NONCE_SIZE],
    // Cache in case of hashing
    cache: Option<[u8; BLOCK_WORK_SIZE]>
}

impl<'a> BlockMiner<'a> {
    pub fn new(header_work_hash: Hash, timestamp: TimestampMillis) -> Self {
        Self {
            header_work_hash,
            timestamp,
            nonce: 0,
            miner: None,
            extra_nonce: [0u8; EXTRA_NONCE_SIZE],
            cache: None
        }
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_header_work_hash(&self) -> &Hash {
        &self.header_work_hash
    }

    pub fn get_miner(&self) -> Option<&PublicKey> {
        self.miner.as_ref().map(|m| m.as_ref())
    }

    #[inline(always)]
    pub fn get_pow_hash(&mut self) -> Hash {
        if self.cache.is_none() {
            self.cache = Some(self.to_bytes().try_into().unwrap());
        }

        let bytes = self.cache.as_ref().unwrap();
        // TODO replace with real POW algorithm
        hash(bytes)
    }

    pub fn get_extra_nonce(&mut self) -> &mut [u8; EXTRA_NONCE_SIZE] {
        &mut self.extra_nonce
    }

    #[inline(always)]
    pub fn set_timestamp(&mut self, timestamp: TimestampMillis) {
        self.timestamp = timestamp;
        if let Some(cache) = &mut self.cache {
            cache[32..40].copy_from_slice(&self.timestamp.to_be_bytes());
        }
    }

    #[inline(always)]
    pub fn increase_nonce(&mut self) {
        self.nonce += 1;
        if let Some(cache) = &mut self.cache {
            cache[40..48].copy_from_slice(&self.nonce.to_be_bytes());
        }
    }

    #[inline(always)]
    pub fn set_miner(&mut self, miner: Cow<'a, PublicKey>) {
        self.miner = Some(miner);
    }

    #[inline(always)]
    pub fn set_thread_id(&mut self, id: u8) {
        self.extra_nonce[EXTRA_NONCE_SIZE - 1] = id;
    }

    #[inline(always)]
    pub fn take(self) -> (Hash, TimestampMillis, u64, Option<Cow<'a, PublicKey>>, [u8; EXTRA_NONCE_SIZE]) {
        (self.header_work_hash, self.timestamp, self.nonce, self.miner, self.extra_nonce)
    }
}

impl<'a> Serializer for BlockMiner<'a> {
    fn write(&self, writer: &mut Writer) {
        if let Some(cache) = self.cache {
            writer.write_bytes(&cache);
        } else {
            writer.write_hash(&self.header_work_hash); // 32
            writer.write_u64(&self.timestamp); // 32 + 8 = 40
            writer.write_u64(&self.nonce); // 40 + 8 = 48
            writer.write_bytes(&self.extra_nonce); // 48 + 32 = 80
    
            // 80 + 32 = 112
            if let Some(miner) = &self.miner {
                miner.write(writer);
            } else {
                // We set a 32 bytes empty public key as we don't have any miner
                writer.write_bytes(&[0u8; 32]);
            }
        }

        debug_assert!(writer.total_write() == BLOCK_WORK_SIZE, "invalid block work size, expected {}, got {}", BLOCK_WORK_SIZE, writer.total_write());
    }

    fn read(reader: &mut Reader) -> Result<BlockMiner<'a>, ReaderError> {
        if reader.total_size() != BLOCK_WORK_SIZE {
            return Err(ReaderError::InvalidSize)
        }

        let header_work_hash = reader.read_hash()?;
        let timestamp = reader.read_u64()?;
        let nonce = reader.read_u64()?;
        let extra_nonce = reader.read_bytes_32()?;
        let miner = Some(Cow::Owned(PublicKey::read(reader)?));

        Ok(BlockMiner {
            header_work_hash,
            timestamp,
            nonce,
            extra_nonce,
            miner,
            cache: None
        })
    }
}

// no need to override hash() as its already serialized in good format
impl Hashable for BlockMiner<'_> {}