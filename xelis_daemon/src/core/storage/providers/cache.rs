use async_trait::async_trait;
use crate::core::{error::BlockchainError, storage::cache::ChainCache};
#[macro_export]
macro_rules! clear_caches {
    ($($cache:expr),*) => {
        $( // Repeat for each argument
            if let Some(cache) = $cache.as_mut() {
                cache.get_mut().clear();
            }
        )*
    };
}

#[async_trait]
pub trait CacheProvider {
    // Clear all the internal caches if any
    async fn clear_caches(&mut self) -> Result<(), BlockchainError>;

    async fn chain_cache_mut(&mut self) -> Result<&mut ChainCache, BlockchainError>;

    async fn chain_cache(&self) -> &ChainCache;

    async fn load_caches(&mut self) -> Result<(), BlockchainError>;
}