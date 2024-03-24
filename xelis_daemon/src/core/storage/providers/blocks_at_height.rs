use async_trait::async_trait;
use log::trace;
use xelis_common::{
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::{SledStorage, Tips},
};

#[async_trait]
pub trait BlocksAtHeightProvider {
    // Check if there are blocks at a specific height
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError>;

    // Retrieve the blocks hashes at a specific height
    async fn get_blocks_at_height(&self, height: u64) -> Result<Tips, BlockchainError>;

    // This is used to store the blocks hashes at a specific height
    async fn set_blocks_at_height(&self, tips: Tips, height: u64) -> Result<(), BlockchainError>;

    // Append a block hash at a specific height
    async fn add_block_hash_at_height(&mut self, hash: Hash, height: u64) -> Result<(), BlockchainError>;

    // Remove a block hash at a specific height
    async fn remove_block_hash_at_height(&self, hash: &Hash, height: u64) -> Result<(), BlockchainError>;
}

#[async_trait]
impl BlocksAtHeightProvider for SledStorage {
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError> {
        trace!("get blocks at height {}", height);
        Ok(self.blocks_at_height.contains_key(&height.to_be_bytes())?)
    }

    async fn get_blocks_at_height(&self, height: u64) -> Result<Tips, BlockchainError> {
        trace!("get blocks at height {}", height);
        self.load_from_disk(&self.blocks_at_height, &height.to_be_bytes())
    }

    async fn set_blocks_at_height(&self, tips: Tips, height: u64) -> Result<(), BlockchainError> {
        trace!("set {} blocks at height {}", tips.len(), height);
        self.blocks_at_height.insert(height.to_be_bytes(), tips.to_bytes())?;
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
            Tips::new()
        };

        tips.insert(hash);
        self.set_blocks_at_height(tips, height).await
    }

    async fn remove_block_hash_at_height(&self, hash: &Hash, height: u64) -> Result<(), BlockchainError> {
        trace!("remove block {} at height {}", hash, height);
        let mut tips = self.get_blocks_at_height(height).await?;
        tips.remove(hash);

        // Delete the height if there is no blocks present anymore
        if tips.is_empty() {
            self.blocks_at_height.remove(&height.to_be_bytes())?;
        } else {
            self.set_blocks_at_height(tips, height).await?;
        }

        Ok(())
    }
}