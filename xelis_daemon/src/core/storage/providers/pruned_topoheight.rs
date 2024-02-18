use async_trait::async_trait;
use crate::core::{
    error::BlockchainError,
    storage::{sled::PRUNED_TOPOHEIGHT, SledStorage},
};

// This trait is used for pruning
#[async_trait]
pub trait PrunedTopoheightProvider {
    // get the pruned topoheight
    async fn get_pruned_topoheight(&self) -> Result<Option<u64>, BlockchainError>;

    // set the pruned topoheight on disk
    async fn set_pruned_topoheight(&mut self, pruned_topoheight: u64) -> Result<(), BlockchainError>;
}

#[async_trait]
impl PrunedTopoheightProvider for SledStorage {
    async fn set_pruned_topoheight(&mut self, pruned_topoheight: u64) -> Result<(), BlockchainError> {
        self.pruned_topoheight = Some(pruned_topoheight);
        self.extra.insert(PRUNED_TOPOHEIGHT, &pruned_topoheight.to_be_bytes())?;
        Ok(())
    }

    async fn get_pruned_topoheight(&self) -> Result<Option<u64>, BlockchainError> {
        Ok(self.pruned_topoheight)
    }
}
