use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait VersionedScheduledExecutionsProvider {
    /// Roll back registrations at this topoheight after removing newer registrations.
    async fn delete_scheduled_executions_at_registration_topoheight(&mut self, registration_topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_scheduled_executions_above_registration_topoheight(&mut self, registration_topoheight: TopoHeight) -> Result<(), BlockchainError>;

    /// Delete executions due before the cutoff and their linked registration versions.
    async fn delete_scheduled_executions_below_topoheight(&mut self, execution_topoheight: TopoHeight) -> Result<(), BlockchainError>;
}