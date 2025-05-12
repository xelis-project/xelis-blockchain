use async_trait::async_trait;
use xelis_common::{
    contract::ContractOutput,
    crypto::Hash
};
use crate::core::{
    error::BlockchainError,
    storage::{ContractOutputsProvider, RocksStorage}
};

#[async_trait]
impl ContractOutputsProvider for RocksStorage {
    // Verify if the contract outputs for a transaction exist
    async fn has_contract_outputs_for_tx(&self, tx_hash: &Hash) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Get the contract outputs for a transaction
    async fn get_contract_outputs_for_tx(&self, tx_hash: &Hash) -> Result<Vec<ContractOutput>, BlockchainError> {
        todo!()
    }

    // Set the contract outputs for a transaction
    async fn set_contract_outputs_for_tx(&mut self, tx_hash: &Hash, contract_output: Vec<ContractOutput>) -> Result<(), BlockchainError> {
        todo!()
    }

    // Delete the contract outputs for a transaction
    async fn delete_contract_outputs_for_tx(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError> {
        todo!()
    }
}