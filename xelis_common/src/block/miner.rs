use crate::{crypto::{key::PublicKey, hash::{Hash, Hashable}}, serializer::{Serializer, Writer, Reader, ReaderError}};

use super::{BlockHeader, EXTRA_NONCE_SIZE, BLOCK_WORK_SIZE};

#[derive(Clone, Debug)]
pub struct BlockMiner {
    pub header_work_hash: Hash, // include merkle tree of tips, txs, and height (immutable)
    pub timestamp: u128, // miners can update timestamp to keep it up-to-date
    pub nonce: u64,
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    pub miner: Option<PublicKey>,
}

impl BlockMiner {
    pub fn from_header(header: &BlockHeader) -> Self {
        Self {
            header_work_hash: header.get_header_work_hash(),
            timestamp: header.timestamp,
            nonce: header.nonce,
            extra_nonce: header.extra_nonce,
            miner: None,
        }
    }
}

impl Serializer for BlockMiner {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.header_work_hash);
        writer.write_u128(&self.timestamp);
        writer.write_u64(&self.nonce);
        writer.write_bytes(&self.extra_nonce);

        if let Some(miner) = &self.miner {
            miner.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<BlockMiner, ReaderError> {
        if reader.total_size() != BLOCK_WORK_SIZE {
            return Err(ReaderError::InvalidSize)
        }

        let header_work_hash = reader.read_hash()?;
        let timestamp = reader.read_u128()?;
        let nonce = reader.read_u64()?;
        let extra_nonce: [u8; EXTRA_NONCE_SIZE] = reader.read_bytes_32()?;
        let miner = Some(PublicKey::read(reader)?);

        Ok(BlockMiner {
            header_work_hash,
            timestamp,
            nonce,
            extra_nonce,
            miner,
        })
    }
}

impl Hashable for BlockMiner {}