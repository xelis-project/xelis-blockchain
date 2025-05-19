use std::borrow::Cow;
use async_trait::async_trait;
use indexmap::IndexSet;
use log::error;
use xelis_common::{
    crypto::{Hash, HASH_SIZE},
    serializer::{Reader, ReaderError, Serializer, Writer}
};
use crate::core::error::BlockchainError;

// This struct is used to store the blocks hashes at a specific height
// We use an IndexSet to store the hashes and maintains the order we processed them
#[derive(Default)]
pub struct OrderedHashes<'a>(pub Cow<'a, IndexSet<Hash>>);

#[async_trait]
pub trait BlocksAtHeightProvider {
    // Check if there are blocks at a specific height
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError>;

    // Retrieve the blocks hashes at a specific height
    async fn get_blocks_at_height(&self, height: u64) -> Result<IndexSet<Hash>, BlockchainError>;

    // This is used to store the blocks hashes at a specific height
    async fn set_blocks_at_height(&mut self, tips: &IndexSet<Hash>, height: u64) -> Result<(), BlockchainError>;

    // Append a block hash at a specific height
    async fn add_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError>;

    // Remove a block hash at a specific height
    async fn remove_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError>;
}

impl Serializer for OrderedHashes<'_> {
    fn write(&self, writer: &mut Writer) {
        for hash in self.0.iter() {
            hash.write(writer);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let total_size = reader.total_size();
        if total_size % HASH_SIZE != 0 {
            error!("Invalid size: {}, expected a multiple of 32 for hashes", total_size);
            return Err(ReaderError::InvalidSize)
        }

        let count = total_size / HASH_SIZE;
        let mut hashes = IndexSet::with_capacity(count);
        for _ in 0..count {
            hashes.insert(Hash::read(reader)?);
        }

        if hashes.len() != count {
            error!("Invalid size: received {} elements while sending {}", hashes.len(), count);
            return Err(ReaderError::InvalidSize) 
        }

        Ok(OrderedHashes(Cow::Owned(hashes)))
    }
}