use async_trait::async_trait;
use log::debug;

use crate::core::{error::BlockchainError, storage::SledStorage};

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
}

#[async_trait]
impl CacheProvider for SledStorage {
    async fn clear_caches(&mut self) -> Result<(), BlockchainError> {
        debug!("clear caches");
        clear_caches!(
            self.transactions_cache,
            self.blocks_cache,
            self.past_blocks_cache,
            self.topo_by_hash_cache,
            self.hash_at_topo_cache,
            self.cumulative_difficulty_cache,
            self.assets_cache
        );

        // also load the atomic counters from disk
        self.load_cache_from_disk();

        Ok(())
    }
}