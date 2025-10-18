use async_trait::async_trait;
use log::{trace, debug};

use crate::core::{
    error::BlockchainError,
    storage::{CacheProvider, ChainCache, SledStorage}
};

#[async_trait]
impl CacheProvider for SledStorage {
    async fn clear_caches(&mut self) -> Result<(), BlockchainError> {
        debug!("clear caches");
        self.cache_mut().clear_caches();

        debug!("reload caches from disk");
        // also load the atomic counters from disk
        self.load_cache_from_disk();

        Ok(())
    }

    async fn chain_cache_mut(&mut self) -> Result<&mut ChainCache, BlockchainError> {
        Ok(&mut self.cache_mut().chain)
    }

    async fn chain_cache(&self) -> &ChainCache {
        &self.cache().chain
    }

    async fn load_caches(&mut self) -> Result<(), BlockchainError> {
        trace!("load caches");

        Ok(())
    }
}