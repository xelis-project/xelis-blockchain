use async_trait::async_trait;
use crate::core::{error::BlockchainError, storage::cache::ChainCache};

#[async_trait]
pub trait CacheProvider {
    // Clear all the internal caches if any
    async fn clear_objects_cache(&mut self) -> Result<(), BlockchainError>;

    async fn chain_cache_mut(&mut self) -> Result<&mut ChainCache, BlockchainError>;

    async fn chain_cache(&self) -> &ChainCache;
}