use crate::crypto::hash::Hash;
use super::{Serializer, Writer, Reader, ReaderError};
use std::collections::HashSet;
use log::error;

impl Serializer for HashSet<Hash> {
    fn write(&self, writer: &mut Writer) {
        for hash in self {
            writer.write_hash(hash);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let total_size = reader.total_size();
        if total_size % 32 != 0 {
            error!("Invalid size: {}, expected a multiple of 32 for hashes", total_size);
            return Err(ReaderError::InvalidSize)
        }

        let count = total_size / 32;
        let mut tips = HashSet::with_capacity(count);
        for _ in 0..count {
            let hash = reader.read_hash()?;
            tips.insert(hash);
        }
        Ok(tips)
    }
}

// Implement Serializer for u64
impl Serializer for u64 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u64()?)
    }
}