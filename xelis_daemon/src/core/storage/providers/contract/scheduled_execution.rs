use async_trait::async_trait;
use xelis_common::{block::TopoHeight, contract::ScheduledExecution, crypto::Hash};

use crate::core::error::BlockchainError;

#[async_trait]
pub trait ContractScheduledExecutionProvider {
    // Set contract delayed execution at provided topoheight
    // Caller must ensures that the topoheight configured is >= current topoheight
    async fn set_contract_scheduled_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &ScheduledExecution, execution_topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Has a contract delayed execution registered at the provided topoheight?
    // only one delayed execution per contract and per topoheight can exist.
    async fn has_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the contract delayed execution registered at the provided topoheight
    async fn get_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<ScheduledExecution, BlockchainError>;

    // Get the registered delayed executions at the provided topoheight
    async fn get_registered_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError>;

    // Get the delayed executions planned for the provided topoheight
    async fn get_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError>;
}