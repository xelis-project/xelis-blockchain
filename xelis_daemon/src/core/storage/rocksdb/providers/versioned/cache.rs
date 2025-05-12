use async_trait::async_trait;
use crate::core::{error::BlockchainError, storage::{RocksStorage, VersionedCacheProvider}};

#[async_trait]
impl VersionedCacheProvider for RocksStorage {
    // Clear all the internal caches if any
    async fn clear_versioned_data_caches(&mut self) -> Result<(), BlockchainError> {
        Ok(())
    }
}