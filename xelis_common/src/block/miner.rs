use std::borrow::Cow;

use crate::{crypto::{hash::{Hash, Hashable, hash}, key::PublicKey}, serializer::{Serializer, Writer, Reader, ReaderError}};

use super::{EXTRA_NONCE_SIZE, BLOCK_WORK_SIZE};

// This structure is used by xelis-miner which allow to compute a valid block POW hash
#[derive(Clone, Debug)]
pub struct BlockMiner<'a> {
    pub header_work_hash: Hash, // include merkle tree of tips, txs, and height (immutable)
    pub timestamp: u128, // miners can update timestamp to keep it up-to-date
    pub nonce: u64,
    pub miner: Option<Cow<'a, PublicKey>>,
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE]
}

impl<'a> BlockMiner<'a> {
    pub fn new(header_work_hash: Hash, timestamp: u128) -> Self {
        Self {
            header_work_hash,
            timestamp,
            nonce: 0,
            miner: None,
            extra_nonce: [0u8; EXTRA_NONCE_SIZE]
        }
    }

    #[inline(always)]
    pub fn get_pow_hash(&self) -> Hash {
        // TODO replace with real POW algorithm
        hash(&self.to_bytes())
    }
}

impl<'a> Serializer for BlockMiner<'a> {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.header_work_hash); // 32
        writer.write_u128(&self.timestamp); // 32 + 16 = 48
        writer.write_u64(&self.nonce); // 48 + 8 = 56
        writer.write_bytes(&self.extra_nonce); // 56 + 32 = 88

        if let Some(miner) = &self.miner {
            miner.write(writer); // 88 + 32 = 120
        }

        debug_assert!(writer.total_write() == BLOCK_WORK_SIZE, "invalid block work size");
    }

    fn read(reader: &mut Reader) -> Result<BlockMiner<'a>, ReaderError> {
        if reader.total_size() != BLOCK_WORK_SIZE {
            return Err(ReaderError::InvalidSize)
        }

        let header_work_hash = reader.read_hash()?;
        let timestamp = reader.read_u128()?;
        let nonce = reader.read_u64()?;
        let extra_nonce = reader.read_bytes_32()?;
        let miner = Some(Cow::Owned(PublicKey::read(reader)?));

        Ok(BlockMiner {
            header_work_hash,
            timestamp,
            nonce,
            extra_nonce,
            miner
        })
    }
}

// no need to override hash() as its already serialized in good format
impl Hashable for BlockMiner<'_> {}