use async_trait::async_trait;
use indexmap::IndexSet;
use log::{error, trace};
use xelis_common::{
    crypto::{Hash, HASH_SIZE},
    serializer::{Reader, ReaderError, Serializer, Writer}
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage,
};

// This struct is used to store the blocks hashes at a specific height
// We use an IndexSet to store the hashes and maintains the order we processed them
struct OrderedHashes(IndexSet<Hash>);

#[async_trait]
pub trait BlocksAtHeightProvider {
    // Check if there are blocks at a specific height
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError>;

    // Retrieve the blocks hashes at a specific height
    async fn get_blocks_at_height(&self, height: u64) -> Result<IndexSet<Hash>, BlockchainError>;

    // This is used to store the blocks hashes at a specific height
    async fn set_blocks_at_height(&mut self, tips: IndexSet<Hash>, height: u64) -> Result<(), BlockchainError>;

    // Append a block hash at a specific height
    async fn add_block_hash_at_height(&mut self, hash: Hash, height: u64) -> Result<(), BlockchainError>;

    // Remove a block hash at a specific height
    async fn remove_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError>;
}

#[async_trait]
impl BlocksAtHeightProvider for SledStorage {
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError> {
        trace!("get blocks at height {}", height);
        self.contains_data(&self.blocks_at_height, &height.to_be_bytes())
    }

    async fn get_blocks_at_height(&self, height: u64) -> Result<IndexSet<Hash>, BlockchainError> {
        trace!("get blocks at height {}", height);
        let hashes: OrderedHashes = self.load_from_disk(&self.blocks_at_height, &height.to_be_bytes(), DiskContext::BlocksAtHeight)?;
        Ok(hashes.0)
    }

    async fn set_blocks_at_height(&mut self, tips: IndexSet<Hash>, height: u64) -> Result<(), BlockchainError> {
        trace!("set {} blocks at height {}", tips.len(), height);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.blocks_at_height, &height.to_be_bytes(), OrderedHashes(tips).to_bytes())?;
        Ok(())
    }

    async fn add_block_hash_at_height(&mut self, hash: Hash, height: u64) -> Result<(), BlockchainError> {
        trace!("add block {} at height {}", hash, height);
        let mut tips = if self.has_blocks_at_height(height).await? {
            let hashes = self.get_blocks_at_height(height).await?;
            trace!("Found {} blocks at this height", hashes.len());
            hashes
        } else {
            trace!("No blocks found at this height");
            IndexSet::new()
        };

        tips.insert(hash);
        self.set_blocks_at_height(tips, height).await
    }

    async fn remove_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError> {
        trace!("remove block {} at height {}", hash, height);
        let mut tips = self.get_blocks_at_height(height).await?;
        tips.shift_remove(hash);

        // Delete the height if there is no blocks present anymore
        if tips.is_empty() {
            Self::delete_data_without_reading(self.snapshot.as_mut(), &self.blocks_at_height, &height.to_be_bytes())?;
        } else {
            self.set_blocks_at_height(tips, height).await?;
        }

        Ok(())
    }
}

impl Serializer for OrderedHashes {
    fn write(&self, writer: &mut Writer) {
        for hash in &self.0 {
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

        Ok(OrderedHashes(hashes))
    }
}