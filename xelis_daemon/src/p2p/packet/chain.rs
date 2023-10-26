use log::debug;
use xelis_common::{
    crypto::hash::Hash,
    serializer::{
        Serializer,
        Writer,
        ReaderError,
        Reader
    },
};
use crate::config::{CHAIN_SYNC_REQUEST_MAX_BLOCKS, CHAIN_SYNC_RESPONSE_MAX_BLOCKS, CHAIN_SYNC_TOP_BLOCKS, TIPS_LIMIT};

#[derive(Clone, Debug)]
pub struct BlockId {
    hash: Hash,
    topoheight: u64
}

impl BlockId {
    pub fn new(hash: Hash, topoheight: u64) -> Self {
        Self {
            hash,
            topoheight
        }
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }

    pub fn consume(self) -> (Hash, u64) {
        (self.hash, self.topoheight)
    }
}

impl Serializer for BlockId {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(self.get_hash());
        writer.write_u64(&self.get_topoheight());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self::new(reader.read_hash()?, reader.read_u64()?))
    }
}

#[derive(Clone, Debug)]
pub struct ChainRequest {
    blocks: Vec<BlockId>
}

impl ChainRequest {
    pub fn new(blocks: Vec<BlockId>) -> Self {
        Self {
            blocks
        }
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
        if len == 0 || len > CHAIN_SYNC_REQUEST_MAX_BLOCKS as u8 {
            debug!("Invalid chain request length: {}", len);
            return Err(ReaderError::InvalidValue)
        }

        let mut blocks = Vec::with_capacity(len as usize);
        for _ in 0..len {
            blocks.push(BlockId::read(reader)?);
        }
        Ok(Self { blocks })
    }
}

#[derive(Debug)]
pub struct CommonPoint {
    hash: Hash,
    topoheight: u64
}

impl CommonPoint {
    pub fn new(hash: Hash, topoheight: u64) -> Self {
        Self {
            hash,
            topoheight
        }
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_topoheight(&self) -> u64 {
        self.topoheight
    }
}

impl Serializer for CommonPoint {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.hash);
        writer.write_u64(&self.topoheight);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hash = reader.read_hash()?;
        let topoheight = reader.read_u64()?;
        Ok(Self { hash, topoheight })
    }
}

#[derive(Debug)]
pub struct ChainResponse {
    common_point: Option<CommonPoint>,
    blocks: Vec<Hash>,
    top_blocks: Vec<Hash>
}

impl ChainResponse {
    pub fn new(common_point: Option<CommonPoint>, blocks: Vec<Hash>, top_blocks:Vec<Hash>) -> Self {
        Self {
            common_point,
            blocks,
            top_blocks
        }
    }

    pub fn get_common_point(&mut self) -> Option<CommonPoint> {
        self.common_point.take()
    }

    pub fn size(&self) -> usize {
        self.blocks.len()
    }

    pub fn consume(self) -> (Vec<Hash>, Vec<Hash>) {
        (self.blocks, self.top_blocks)
    }
}

impl Serializer for ChainResponse {
    fn write(&self, writer: &mut Writer) {
        self.common_point.write(writer);
        writer.write_u16(self.blocks.len() as u16);
        for hash in &self.blocks {
            writer.write_hash(hash);
        }

        writer.write_u8(self.top_blocks.len() as u8);
        for hash in &self.top_blocks {
            writer.write_hash(hash);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let common_point = Option::read(reader)?;
        let len = reader.read_u16()?;
        if len > CHAIN_SYNC_RESPONSE_MAX_BLOCKS as u16 {
            debug!("Invalid chain response length: {}", len);
            return Err(ReaderError::InvalidValue)
        }

        let mut blocks: Vec<Hash> = Vec::with_capacity(len as usize); 
        for _ in 0..len {
            let hash = reader.read_hash()?;
            blocks.push(hash);
        }

        let len = reader.read_u8()?;
        if len > (CHAIN_SYNC_TOP_BLOCKS * TIPS_LIMIT) as u8 {
            debug!("Invalid chain response top blocks length: {}", len);
            return Err(ReaderError::InvalidValue)
        }

        let mut top_blocks: Vec<Hash> = Vec::with_capacity(len as usize); 
        for _ in 0..len {
            let hash = reader.read_hash()?;
            top_blocks.push(hash);
        }

        Ok(Self::new(common_point, blocks, top_blocks))
    }
}