use async_trait::async_trait;
use log::debug;

use crate::{
    core::{error::BlockchainError, storage::SledStorage},
    clear_caches
};

#[async_trait]
pub trait VersionedCacheProvider {
    // Clear all the internal caches if any
    async fn clear_versioned_data_caches(&mut self) -> Result<(), BlockchainError>;   
}

#[async_trait]
impl VersionedCacheProvider for SledStorage {
    async fn clear_versioned_data_caches(&mut self) -> Result<(), BlockchainError> {
        debug!("clear versioned data caches");
        clear_caches!(
            self.topo_by_hash_cache,
            self.hash_at_topo_cache,
            self.assets_cache
        );

        Ok(())
    }
}