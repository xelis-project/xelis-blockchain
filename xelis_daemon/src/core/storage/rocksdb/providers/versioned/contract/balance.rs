use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        RocksStorage,
        VersionedContractBalanceProvider
    }
};

#[async_trait]
impl VersionedContractBalanceProvider for RocksStorage {
    async fn delete_versioned_contract_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contract balances at topoheight {}", topoheight);
        self.delete_versioned_at_topoheight(Column::ContractsBalances, Column::VersionedContractsBalances, topoheight)
    }

    async fn delete_versioned_contract_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contract balances above topoheight {}", topoheight);
        self.delete_versioned_above_topoheight(Column::ContractsBalances, Column::VersionedContractsBalances, topoheight)
    }

    async fn delete_versioned_contract_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contract balances below topoheight {}", topoheight);
        self.delete_versioned_below_topoheight(Column::ContractsBalances, Column::VersionedContractsBalances, topoheight, keep_last)
    }
}