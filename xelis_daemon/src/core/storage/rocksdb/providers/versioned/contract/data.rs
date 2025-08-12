use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        RocksStorage,
        VersionedContractDataProvider
    }
};

#[async_trait]
impl VersionedContractDataProvider for RocksStorage {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contract data at topoheight {}", topoheight);
        self.delete_versioned_at_topoheight(Column::ContractsStorage, Column::VersionedContractsData, topoheight)
    }

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contract data above topoheight {}", topoheight);
        self.delete_versioned_above_topoheight(Column::ContractsStorage, Column::VersionedContractsData, topoheight)
    }

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contract data below topoheight {}", topoheight);
        self.delete_versioned_below_topoheight(Column::ContractsStorage, Column::VersionedContractsData, topoheight, keep_last)
    }
}