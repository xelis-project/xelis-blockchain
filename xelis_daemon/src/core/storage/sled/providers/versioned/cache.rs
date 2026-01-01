use async_trait::async_trait;
use log::debug;

use crate::core::{
    error::BlockchainError,
    storage::{SledStorage, VersionedCacheProvider}
};

#[async_trait]
impl VersionedCacheProvider for SledStorage {
    async fn clear_versioned_data_caches(&mut self) -> Result<(), BlockchainError> {
        debug!("clear versioned data caches");

        self.cache_mut().clear_caches();
        Ok(())
    }
}