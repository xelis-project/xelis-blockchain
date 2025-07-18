use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

// This trait is used for pruning
#[async_trait]
pub trait PrunedTopoheightProvider {
    // get the pruned topoheight
    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError>;

    // set the pruned topoheight on disk
    async fn set_pruned_topoheight(&mut self, pruned_topoheight: Option<TopoHeight>) -> Result<(), BlockchainError>;
}