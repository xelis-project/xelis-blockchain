use async_trait::async_trait;
use xelis_common::{
    crypto::Hash,
    block::TopoHeight,
};
use crate::core::error::BlockchainError;

// This trait is used for find_tip_work_score to provide topoheight of each blocks
#[async_trait]
pub trait DagOrderProvider {
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError>;
    async fn set_topo_height_for_block(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError>;
    async fn is_block_topological_ordered(&self, hash: &Hash) -> bool;
    async fn get_hash_at_topo_height(&self, topoheight: TopoHeight) -> Result<Hash, BlockchainError>;
    async fn has_hash_at_topoheight(&self, topoheight: TopoHeight) -> Result<bool, BlockchainError>;
}