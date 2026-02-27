use async_trait::async_trait;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedCacheProvider, MemoryStorage},
};

#[async_trait]
impl VersionedCacheProvider for MemoryStorage {
    async fn clear_versioned_data_caches(&mut self) -> Result<(), BlockchainError> {
        // No caching in memory storage
        Ok(())
    }
}
