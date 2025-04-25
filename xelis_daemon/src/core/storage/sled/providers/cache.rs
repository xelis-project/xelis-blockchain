use async_trait::async_trait;
use log::debug;

use crate::{clear_caches, core::{error::BlockchainError, storage::{CacheProvider, SledStorage}}};

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