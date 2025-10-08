use async_trait::async_trait;
use log::trace;
use xelis_common::{
    contract::ContractLog,
    crypto::Hash
};
use crate::core::{
    error::BlockchainError,
    storage::{rocksdb::Column, ContractLogsProvider, RocksStorage}
};

#[async_trait]
impl ContractLogsProvider for RocksStorage {
    // Verify if the contract outputs for a transaction exist
    async fn has_contract_logs_for_tx(&self, tx_hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has contract outputs for tx {}", tx_hash);
        self.contains_data(Column::ContractLogs, tx_hash)
    }

    // Get the contract outputs for a transaction
    async fn get_contract_logs_for_tx(&self, tx_hash: &Hash) -> Result<Vec<ContractLog>, BlockchainError> {
        trace!("get contract outputs for tx {}", tx_hash);
        self.load_from_disk(Column::ContractLogs, tx_hash)
    }

    // Set the contract outputs for a transaction
    async fn set_contract_logs_for_tx(&mut self, tx_hash: &Hash, contract_output: &Vec<ContractLog>) -> Result<(), BlockchainError> {
        trace!("set contract outputs for tx {}", tx_hash);
        self.insert_into_disk(Column::ContractLogs, tx_hash, contract_output)
    }

    // Delete the contract outputs for a transaction
    async fn delete_contract_logs_for_tx(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError> {
        trace!("delete contract outputs for tx {}", tx_hash);
        self.remove_from_disk(Column::ContractLogs, tx_hash)
    }
}