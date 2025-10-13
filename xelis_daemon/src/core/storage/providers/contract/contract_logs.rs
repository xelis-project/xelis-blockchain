use async_trait::async_trait;
use xelis_common::{
    contract::ContractLog,
    crypto::Hash
};
use crate::core::error::BlockchainError;

#[async_trait]
pub trait ContractLogsProvider {
    // Verify if the contract logs for a caller exist
    async fn has_contract_logs_for_caller(&self, caller: &Hash) -> Result<bool, BlockchainError>;

    // Get the contract logs for a caller
    async fn get_contract_logs_for_caller(&self, caller: &Hash) -> Result<Vec<ContractLog>, BlockchainError>;

    // Set the contract logs for a caller
    async fn set_contract_logs_for_caller(&mut self, caller: &Hash, logs: &Vec<ContractLog>) -> Result<(), BlockchainError>;

    // Delete the contract outputs for a caller
    async fn delete_contract_logs_for_caller(&mut self, caller: &Hash) -> Result<(), BlockchainError>;
}