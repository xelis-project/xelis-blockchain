use async_trait::async_trait;
use indexmap::IndexSet;
use log::trace;
use xelis_common::{
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{BlocksAtHeightProvider, OrderedHashes, SledStorage},
};

#[async_trait]
impl BlocksAtHeightProvider for SledStorage {
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError> {
        trace!("get blocks at height {}", height);
        self.contains_data(&self.blocks_at_height, &height.to_be_bytes())
    }

    async fn get_blocks_at_height(&self, height: u64) -> Result<IndexSet<Hash>, BlockchainError> {
        trace!("get blocks at height {}", height);
        let hashes: OrderedHashes = self.load_from_disk(&self.blocks_at_height, &height.to_be_bytes(), DiskContext::BlocksAtHeight(height))?;
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
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.blocks_at_height, &height.to_be_bytes())?;
        } else {
            self.set_blocks_at_height(tips, height).await?;
        }

        Ok(())
    }
}