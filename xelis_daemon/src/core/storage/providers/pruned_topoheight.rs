use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{sled::PRUNED_TOPOHEIGHT, SledStorage},
};

// This trait is used for pruning
#[async_trait]
pub trait PrunedTopoheightProvider {
    // get the pruned topoheight
    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError>;

    // set the pruned topoheight on disk
    async fn set_pruned_topoheight(&mut self, pruned_topoheight: TopoHeight) -> Result<(), BlockchainError>;
}

#[async_trait]
impl PrunedTopoheightProvider for SledStorage {
    async fn set_pruned_topoheight(&mut self, pruned_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.cache.pruned_topoheight = Some(pruned_topoheight);
        } else {
            self.cache.pruned_topoheight = Some(pruned_topoheight);
        }

        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, PRUNED_TOPOHEIGHT, &pruned_topoheight.to_be_bytes())?;
        Ok(())
    }

    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.cache.pruned_topoheight)
    }
}
