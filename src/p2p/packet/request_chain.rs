use crate::core::reader::{Reader, ReaderError};
use crate::core::serializer::Serializer;
use crate::crypto::hash::Hash;

pub struct RequestChain {
    start: u64,
    end: u64,
    top_hash: Hash,
}

impl RequestChain {
    pub fn new(start: u64, end: u64, top_hash: Hash) -> Self {
        assert!(start <= end);
        Self {
            start,
            end,
            top_hash
        }
    }

    pub fn get_start_height(&self) -> u64 {
        self.start        
    }

    pub fn get_end_height(&self) -> u64 {
        self.end
    }

    pub fn get_top_hash(&self) -> &Hash {
        &self.top_hash
    }
}

impl Serializer for RequestChain {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.start.to_be_bytes());
        bytes.extend(self.end.to_be_bytes());
        bytes.extend(self.top_hash.as_bytes());
        bytes
    }

    fn from_bytes(reader: &mut Reader) -> Result<Self, ReaderError> {
        let start = reader.read_u64()?;
        let end = reader.read_u64()?;
        if start > end {
            return Err(ReaderError::InvalidValue)
        }

        let top_hash = reader.read_hash()?;
        Ok(Self { start, end, top_hash })
    }
}