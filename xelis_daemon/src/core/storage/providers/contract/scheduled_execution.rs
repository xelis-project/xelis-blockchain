use async_trait::async_trait;
use futures::Stream;
use xelis_common::{block::TopoHeight, contract::ScheduledExecution, crypto::Hash};

use crate::core::error::BlockchainError;

#[async_trait]
pub trait ContractScheduledExecutionProvider {
    // Set contract scheduled execution at provided topoheight
    // Caller must ensures that the topoheight configured is >= current topoheight
    async fn set_contract_scheduled_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &ScheduledExecution, execution_topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Has a contract scheduled execution registered at the provided topoheight?
    // only one scheduled execution per contract and per topoheight can exist.
    async fn has_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the contract scheduled execution registered at the provided topoheight
    async fn get_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<ScheduledExecution, BlockchainError>;

    // Get the registered scheduled executions at the provided topoheight
    async fn get_registered_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError>;

    // Get the scheduled executions planned for the provided topoheight
    async fn get_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError>;

    // Get the registered scheduled executions at maximum topoheight (inclusive)
    // Returns a stream of (execution_topoheight, registration_topoheight, execution)
    async fn get_registered_contract_scheduled_executions_in_range<'a>(&'a self, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<impl Stream<Item = Result<(TopoHeight, TopoHeight, ScheduledExecution), BlockchainError>> + Send + 'a, BlockchainError>;
}