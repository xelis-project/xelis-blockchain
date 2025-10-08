use async_trait::async_trait;
use xelis_common::{
    contract::ContractLog,
    crypto::Hash
};
use crate::core::error::BlockchainError;

#[async_trait]
pub trait ContractLogsProvider {
    // Verify if the contract logs for a transaction exist
    async fn has_contract_logs_for_tx(&self, tx_hash: &Hash) -> Result<bool, BlockchainError>;

    // Get the contract logs for a transaction
    async fn get_contract_logs_for_tx(&self, tx_hash: &Hash) -> Result<Vec<ContractLog>, BlockchainError>;

    // Set the contract logs for a transaction
    async fn set_contract_logs_for_tx(&mut self, tx_hash: &Hash, logs: &Vec<ContractLog>) -> Result<(), BlockchainError>;

    // Delete the contract outputs for a transaction
    async fn delete_contract_logs_for_tx(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError>;
}