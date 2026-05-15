use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::error::BlockchainError;

/// Abstracts the DAG-order and pruning lookups needed to resolve the best
/// topoheight for a transaction reference.
#[async_trait]
pub trait ReferenceProvider: Send + Sync {
    /// Whether the given block hash has been assigned a topoheight in the DAG order.
    async fn is_block_topological_ordered(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    /// Get the topoheight assigned to a block hash.
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError>;

    /// Get the current pruned topoheight, if any.
    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError>;
}
