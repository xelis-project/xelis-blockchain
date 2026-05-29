use async_trait::async_trait;
use crate::core::{
    error::BlockchainError,
    storage::{CacheProvider, cache::ChainCache},
};
use super::super::MemoryStorage;

#[async_trait]
impl CacheProvider for MemoryStorage {
    async fn clear_objects_cache(&mut self) -> Result<(), BlockchainError> {
        self.cache.clear_caches();
        Ok(())
    }

    async fn chain_cache_mut(&mut self) -> Result<&mut ChainCache, BlockchainError> {
        Ok(&mut self.cache)
    }

    async fn chain_cache(&self) -> &ChainCache {
        &self.cache
    }
}
