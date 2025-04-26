use async_trait::async_trait;
use xelis_common::{
    contract::ContractOutput,
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage
};

#[async_trait]
pub trait ContractOutputsProvider {
    // Verify if the contract outputs for a transaction exist
    async fn has_contract_outputs_for_tx(&self, tx_hash: &Hash) -> Result<bool, BlockchainError>;

    // Get the contract outputs for a transaction
    async fn get_contract_outputs_for_tx(&self, tx_hash: &Hash) -> Result<Vec<ContractOutput>, BlockchainError>;

    // Set the contract outputs for a transaction
    async fn set_contract_outputs_for_tx(&mut self, tx_hash: &Hash, contract_output: Vec<ContractOutput>) -> Result<(), BlockchainError>;

    // Delete the contract outputs for a transaction
    async fn delete_contract_outputs_for_tx(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError>;
}

#[async_trait]
impl ContractOutputsProvider for SledStorage {
    async fn has_contract_outputs_for_tx(&self, tx_hash: &Hash) -> Result<bool, BlockchainError> {
        self.contains_data(&self.contracts_outputs, tx_hash.as_bytes())
    }

    async fn get_contract_outputs_for_tx(&self, tx_hash: &Hash) -> Result<Vec<ContractOutput>, BlockchainError> {
        self.load_from_disk(&self.contracts_outputs, tx_hash.as_bytes(), DiskContext::ContractOutputs)
    }

    async fn set_contract_outputs_for_tx(&mut self, tx_hash: &Hash, contract_output: Vec<ContractOutput>) -> Result<(), BlockchainError> {
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_outputs, tx_hash.as_bytes(), contract_output.to_bytes())?;
        Ok(())
    }

    async fn delete_contract_outputs_for_tx(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError> {
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_outputs, tx_hash.as_bytes())?;
        Ok(())
    }
}