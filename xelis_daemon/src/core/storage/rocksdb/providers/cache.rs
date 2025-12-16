use async_trait::async_trait;
use log::trace;
use crate::core::{
    error::BlockchainError,
    storage::{CacheProvider, ChainCache, RocksStorage}
};

#[async_trait]
impl CacheProvider for RocksStorage {
    // Clear all the internal caches if any
    async fn clear_objects_cache(&mut self) -> Result<(), BlockchainError> {
        trace!("clear caches");
        self.cache_mut().clear_caches();
        Ok(())
    }

    async fn chain_cache_mut(&mut self) -> Result<&mut ChainCache, BlockchainError> {
        Ok(&mut self.cache_mut().chain)
    }

    async fn chain_cache(&self) -> &ChainCache {
        &self.cache().chain
    }
}