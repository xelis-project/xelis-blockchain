use log::trace;
use async_trait::async_trait;
use xelis_common::{
    contract::ContractLog,
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{ContractLogsProvider, SledStorage}
};

#[async_trait]
impl ContractLogsProvider for SledStorage {
    async fn has_contract_logs_for_caller(&self, tx_hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has contract logs exist for caller {}", tx_hash);
        self.contains_data(&self.contracts_logs, tx_hash.as_bytes())
    }

    async fn get_contract_logs_for_caller(&self, tx_hash: &Hash) -> Result<Vec<ContractLog>, BlockchainError> {
        trace!("get contract logs for caller {}", tx_hash);
        self.load_from_disk(&self.contracts_logs, tx_hash.as_bytes(), DiskContext::ContractOutputs)
    }

    async fn set_contract_logs_for_caller(&mut self, tx_hash: &Hash, contract_output: &Vec<ContractLog>) -> Result<(), BlockchainError> {
        trace!("set contract logs for caller {}", tx_hash);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_logs, tx_hash.as_bytes(), contract_output.to_bytes())?;
        Ok(())
    }

    async fn delete_contract_logs_for_caller(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError> {
        trace!("delete contract logs for caller {}", tx_hash);
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_logs, tx_hash.as_bytes())?;
        Ok(())
    }
}