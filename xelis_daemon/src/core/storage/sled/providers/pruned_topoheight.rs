use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{sled::PRUNED_TOPOHEIGHT, PrunedTopoheightProvider, SledStorage},
};

#[async_trait]
impl PrunedTopoheightProvider for SledStorage {
    async fn set_pruned_topoheight(&mut self, pruned_topoheight: Option<TopoHeight>) -> Result<(), BlockchainError> {
        self.cache_mut().pruned_topoheight = pruned_topoheight;

        if let Some(pruned_topoheight) = pruned_topoheight {
            Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, PRUNED_TOPOHEIGHT, &pruned_topoheight.to_be_bytes())?;
        } else {
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.extra, PRUNED_TOPOHEIGHT)?;
        }
        Ok(())
    }

    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.cache.pruned_topoheight)
    }
}
