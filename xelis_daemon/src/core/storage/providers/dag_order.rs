use async_trait::async_trait;
use xelis_common::{
    crypto::Hash,
    block::TopoHeight,
};
use crate::core::error::BlockchainError;

// This trait is used for find_tip_work_score to provide topoheight of each blocks
#[async_trait]
pub trait DagOrderProvider {
    // Get the topoheight from a block hash
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError>;

    // Set the topoheight for a block hash
    async fn set_topo_height_for_block(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Is block hash ordered in DAG?
    // (block hash must be assigned a topoheight)
    async fn is_block_topological_ordered(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Get the current block hash at specified topoheight
    async fn get_hash_at_topo_height(&self, topoheight: TopoHeight) -> Result<Hash, BlockchainError>;

    // Is topoheight available
    async fn has_hash_at_topoheight(&self, topoheight: TopoHeight) -> Result<bool, BlockchainError>;
}