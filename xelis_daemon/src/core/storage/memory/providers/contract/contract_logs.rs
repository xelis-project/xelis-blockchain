use pooled_arc::PooledArc;
use async_trait::async_trait;
use anyhow::Context;
use xelis_common::{
    contract::ContractLog,
    crypto::Hash,
};
use crate::core::{
    error::BlockchainError,
    storage::ContractLogsProvider,
};
use super::super::super::MemoryStorage;

#[async_trait]
impl ContractLogsProvider for MemoryStorage {
    async fn has_contract_logs_for_caller(&self, tx_hash: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.contract_logs.contains_key(tx_hash))
    }

    async fn get_contract_logs_for_caller(&self, tx_hash: &Hash) -> Result<Vec<ContractLog>, BlockchainError> {
        self.contract_logs.get(tx_hash)
            .cloned()
            .with_context(|| format!("Contract logs not found for transaction {:?}", tx_hash))
            .map_err(|e| e.into())
    }

    async fn set_contract_logs_for_caller(&mut self, tx_hash: &Hash, logs: &Vec<ContractLog>) -> Result<(), BlockchainError> {
        self.contract_logs.insert(PooledArc::from_ref(tx_hash), logs.clone());
        Ok(())
    }

    async fn delete_contract_logs_for_caller(&mut self, tx_hash: &Hash) -> Result<(), BlockchainError> {
        self.contract_logs.remove(&PooledArc::from_ref(tx_hash));
        Ok(())
    }
}
