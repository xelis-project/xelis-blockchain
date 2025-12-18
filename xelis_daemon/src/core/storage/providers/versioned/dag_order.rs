use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait VersionedDagOrderProvider {
    // Delete the topoheight for a block hash
    async fn delete_dag_order_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Delete every block hashes <=> topoheight relations
    async fn delete_dag_order_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}