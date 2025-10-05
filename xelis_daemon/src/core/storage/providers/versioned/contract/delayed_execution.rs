use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait VersionedDelayedExecutionsProvider {
    async fn delete_delayed_executions_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_delayed_executions_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_delayed_executions_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}