use async_trait::async_trait;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait VersionedCacheProvider {
    // Clear all the internal caches if any
    async fn clear_versioned_data_caches(&mut self) -> Result<(), BlockchainError>;   
}