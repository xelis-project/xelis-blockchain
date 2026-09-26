use async_trait::async_trait;
use futures::Stream;
use xelis_common::{
    block::TopoHeight,
    contract::ScheduledExecution,
    crypto::Hash,
    versioned::Versioned,
};

use crate::core::error::BlockchainError;

pub type VersionedScheduledExecution = Versioned<ScheduledExecution>;

#[async_trait]
pub trait ContractScheduledExecutionProvider {
    /// Get the topoheight of the latest scheduled execution registered for a contract.
    async fn get_last_contract_scheduled_execution_registration_topoheight(&self, contract: &Hash) -> Result<Option<TopoHeight>, BlockchainError>;

    /// Store a scheduled execution version and update the contract's latest-version pointer.
    async fn set_last_contract_scheduled_execution_at_registration_topoheight(&mut self, contract: &Hash, registration_topoheight: TopoHeight, version: &VersionedScheduledExecution) -> Result<(), BlockchainError>;

    /// Get a scheduled execution version registered at exactly this topoheight.
    async fn get_contract_scheduled_execution_at_exact_registration_topoheight(&self, contract: &Hash, registration_topoheight: TopoHeight) -> Result<VersionedScheduledExecution, BlockchainError>;

    /// Get the latest scheduled execution version registered at or before the requested topoheight.
    async fn get_contract_scheduled_execution_at_maximum_registration_topoheight(&self, contract: &Hash, maximum_registration_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedScheduledExecution)>, BlockchainError> {
        let mut current = self.get_last_contract_scheduled_execution_registration_topoheight(contract).await?;
        while let Some(registration_topoheight) = current {
            let version = self.get_contract_scheduled_execution_at_exact_registration_topoheight(contract, registration_topoheight).await?;
            if registration_topoheight <= maximum_registration_topoheight {
                return Ok(Some((registration_topoheight, version)));
            }
            current = version.get_previous_topoheight();
        }
        Ok(None)
    }

    /// Get the registration topoheight of the latest version at or before the requested topoheight.
    async fn get_contract_scheduled_execution_registration_topoheight_at_maximum_registration_topoheight(&self, contract: &Hash, maximum_registration_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.get_contract_scheduled_execution_at_maximum_registration_topoheight(contract, maximum_registration_topoheight).await?.map(|(registration_topoheight, _)| registration_topoheight))
    }

    /// Check whether a scheduled execution version exists at exactly this registration topoheight.
    async fn has_contract_scheduled_execution_at_exact_registration_topoheight(&self, contract: &Hash, registration_topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    /// Check whether the contract has an execution scheduled for this execution topoheight.
    async fn has_contract_scheduled_execution_at_execution_topoheight(&self, contract: &Hash, execution_topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    /// Register a scheduled execution at a topoheight, linking it to the contract's previous version.
    async fn set_contract_scheduled_execution_at_registration_topoheight(&mut self, contract: &Hash, registration_topoheight: TopoHeight, execution: &ScheduledExecution) -> Result<(), BlockchainError>;

    /// Get the scheduled execution indexed for this contract and execution topoheight.
    async fn get_contract_scheduled_execution_at_execution_topoheight(&self, contract: &Hash, execution_topoheight: TopoHeight) -> Result<Option<ScheduledExecution>, BlockchainError>;

    /// List the contracts with scheduled executions due at this execution topoheight.
    async fn get_contracts_with_scheduled_executions_at_execution_topoheight<'a>(&'a self, execution_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + Send + 'a, BlockchainError>;

    /// List executions registered at this topoheight as `(execution topoheight, contract)` pairs.
    async fn get_contract_scheduled_executions_at_registration_topoheight<'a>(&'a self, registration_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError>;

    /// List scheduled executions due at this execution topoheight.
    async fn get_contract_scheduled_executions_at_execution_topoheight<'a>(&'a self, execution_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError>;

    /// Stream registered versions in a registration-topoheight range, optionally filtering by execution topoheight.
    async fn get_contract_scheduled_executions_in_registration_topoheight_range<'a>(&'a self, minimum_registration_topoheight: TopoHeight, maximum_registration_topoheight: TopoHeight, min_execution_topoheight: Option<TopoHeight>) -> Result<impl Stream<Item = Result<(TopoHeight, TopoHeight, ScheduledExecution), BlockchainError>> + Send + 'a, BlockchainError>;
}
