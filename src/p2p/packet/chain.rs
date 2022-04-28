use std::borrow::Cow;

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

    pub fn get_height(&self) -> u64 {
        self.height
    }

    pub fn consume(self) -> (Hash, u64) {
        (self.hash, self.height)
    }
}

impl Serializer for BlockId {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(self.get_hash());
        writer.write_u64(&self.get_height());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self::new(reader.read_hash()?, reader.read_u64()?))
    }
}

#[derive(Clone)]
pub struct ChainRequest {
    blocks: Vec<BlockId>
}

impl ChainRequest {
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

impl Serializer for ChainRequest {
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

pub struct ChainResponse<'a> {
    common_point: Option<Hash>,
    blocks: Vec<Cow<'a, Hash>>,
}

impl<'a> ChainResponse<'a> {
    pub fn new(common_point: Option<Hash>, blocks: Vec<Cow<'a, Hash>>) -> Self {
        Self {
            common_point,
            blocks
        }
    }

    pub fn get_common_point(&self) -> &Option<Hash> {
        &self.common_point
    }

    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    pub fn get_blocks(self) -> Vec<Cow<'a, Hash>> {
        self.blocks
    }
}

impl<'a> Serializer for ChainResponse<'a> {
    fn write(&self, writer: &mut Writer) {
        match &self.common_point {
            None => {
                writer.write_bool(&false);
            },
            Some(hash) => {
                writer.write_bool(&true);
                writer.write_hash(hash);
            }
        };
        writer.write_u8(self.blocks.len() as u8);
        for hash in &self.blocks {
            writer.write_hash(hash);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let common_point = match reader.read_bool()? {
            true => Some(reader.read_hash()?),
            false => None
        };

        let len = reader.read_u8()?;
        let mut blocks: Vec<Cow<'a, Hash>> = Vec::new(); 
        for _ in 0..len {
            let hash = reader.read_hash()?;
            blocks.push(Cow::Owned(hash));
        }

        Ok(Self::new(common_point, blocks))
    }
}