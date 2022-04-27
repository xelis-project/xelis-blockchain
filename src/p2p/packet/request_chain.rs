use crate::core::reader::{Reader, ReaderError};
use crate::core::serializer::Serializer;
use crate::core::writer::Writer;
use crate::crypto::hash::Hash;

#[derive(Clone)]
pub struct BlockId {
    hash: Hash,
    height: u64
}

impl BlockId {
    pub fn new(hash: Hash, height: u64) -> Self {
        Self {
            hash,
            height
        }
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_height(&self) -> &u64 {
        &self.height
    }
}

impl Serializer for BlockId {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(self.get_height());
        writer.write_hash(self.get_hash());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self::new(reader.read_hash()?, reader.read_u64()?))
    }
}

#[derive(Clone)]
pub struct RequestChain {
    blocks: Vec<BlockId>
}

impl RequestChain {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new()
        }
    }

    pub fn add_block_id(&mut self, hash: Hash, height: u64) {
        self.blocks.push(BlockId {
            hash,
            height
        });
    }

    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    pub fn get_blocks(self) -> Vec<BlockId> {
        self.blocks
    }
}

impl Serializer for RequestChain {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(self.blocks.len() as u8);
        for block_id in &self.blocks {
            block_id.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let len = reader.read_u8()?;
        if len == 0 {
            return Err(ReaderError::InvalidValue)
        }

        let mut blocks = Vec::with_capacity(len as usize);
        for _ in 0..len {
            blocks.push(BlockId::read(reader)?);
        }
        Ok(Self { blocks })
    }
}