use async_trait::async_trait;
use log::trace;
use crate::core::{error::BlockchainError, storage::{CacheProvider, RocksStorage}};

#[async_trait]
impl CacheProvider for RocksStorage {
    // Clear all the internal caches if any
    async fn clear_caches(&mut self) -> Result<(), BlockchainError> {
        trace!("clear caches");
        Ok(())
    }
}