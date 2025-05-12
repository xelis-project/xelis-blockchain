use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{error::BlockchainError, storage::{RocksStorage, VersionedContractBalanceProvider}};

#[async_trait]
impl VersionedContractBalanceProvider for RocksStorage {
    async fn delete_versioned_contract_balances_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn delete_versioned_contract_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    async fn delete_versioned_contract_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        todo!()
    }
}