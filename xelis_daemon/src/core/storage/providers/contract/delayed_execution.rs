use async_trait::async_trait;
use xelis_common::{block::TopoHeight, contract::DelayedExecution, crypto::Hash};

use crate::core::error::BlockchainError;

#[async_trait]
pub trait ContractDelayedExecutionProvider {
    // Set contract delayed execution at provided topoheight
    // Caller must ensures that the topoheight configured is >= current topoheight
    async fn set_contract_delayed_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &DelayedExecution) -> Result<(), BlockchainError>;

    // Has a contract delayed execution registered at the provided topoheight?
    // only one delayed execution per contract and per topoheight can exist.
    async fn has_contract_delayed_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the contract delayed execution registered at the provided topoheight
    async fn get_contract_delayed_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<DelayedExecution, BlockchainError>;
}