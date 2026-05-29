use pooled_arc::PooledArc;
use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::BlocksAtHeightProvider,
};
use super::super::MemoryStorage;

#[async_trait]
impl BlocksAtHeightProvider for MemoryStorage {
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError> {
        Ok(self.blocks_at_height.contains_key(&height))
    }

    async fn get_blocks_at_height(&self, height: u64) -> Result<IndexSet<Hash>, BlockchainError> {
        Ok(self.blocks_at_height.get(&height)
            .map(|s| s.iter().map(|h| h.as_ref().clone()).collect())
            .unwrap_or_default())
    }

    async fn set_blocks_at_height(&mut self, tips: &IndexSet<Hash>, height: u64) -> Result<(), BlockchainError> {
        let shared: IndexSet<_> = tips.iter().map(|h| PooledArc::from_ref(h)).collect();
        self.blocks_at_height.insert(height, shared);
        Ok(())
    }

    async fn add_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(hash);
        self.blocks_at_height
            .entry(height)
            .or_default()
            .insert(shared);
        Ok(())
    }

    async fn remove_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError> {
        if let Some(set) = self.blocks_at_height.get_mut(&height) {
            set.shift_remove(hash);
        }
        Ok(())
    }
}
