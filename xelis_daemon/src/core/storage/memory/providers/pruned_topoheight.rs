use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::PrunedTopoheightProvider,
};
use super::super::MemoryStorage;

#[async_trait]
impl PrunedTopoheightProvider for MemoryStorage {
    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.cache.pruned_topoheight)
    }

    async fn set_pruned_topoheight(&mut self, pruned_topoheight: Option<TopoHeight>) -> Result<(), BlockchainError> {
        self.cache.pruned_topoheight = pruned_topoheight;
        Ok(())
    }
}
