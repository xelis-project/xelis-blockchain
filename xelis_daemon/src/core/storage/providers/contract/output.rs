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
    async fn get_contract_output_for_tx(&self, tx_hash: &Hash) -> Result<Vec<ContractOutput>, BlockchainError>;

    async fn set_contract_output_for_tx(&mut self, tx_hash: &Hash, contract_output: Vec<ContractOutput>) -> Result<(), BlockchainError>;

    async fn delete_contract_output_for_tx(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError>;
}

#[async_trait]
impl ContractOutputsProvider for SledStorage {
    async fn get_contract_output_for_tx(&self, tx_hash: &Hash) -> Result<Vec<ContractOutput>, BlockchainError> {
        self.load_from_disk(&self.contracts_outputs, tx_hash.as_bytes(), DiskContext::ContractOutput)
    }

    async fn set_contract_output_for_tx(&mut self, tx_hash: &Hash, contract_output: Vec<ContractOutput>) -> Result<(), BlockchainError> {
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_outputs, tx_hash.as_bytes(), contract_output.to_bytes())?;
        Ok(())
    }

    async fn delete_contract_output_for_tx(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError> {
        Self::remove_from_disk(self.snapshot.as_mut(), &self.contracts_outputs, tx_hash.as_bytes())?;
        Ok(())
    }
}