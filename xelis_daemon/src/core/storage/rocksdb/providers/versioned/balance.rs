use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        RocksStorage,
        VersionedBalanceProvider
    }
};

#[async_trait]
impl VersionedBalanceProvider for RocksStorage {
    // delete versioned balances at topoheight
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances at topoheight {}", topoheight);
        self.delete_versioned_at_topoheight(Column::Balances, Column::VersionedBalances, topoheight)
    }

    // delete versioned balances above topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances above topoheight {}", topoheight);
        self.delete_versioned_above_topoheight(Column::Balances, Column::VersionedBalances, topoheight)
    }

    // delete versioned balances below topoheight
    // Difference is, if we have
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned balances below topoheight {}", topoheight);
        self.delete_versioned_below_topoheight_default(Column::Balances, Column::VersionedBalances, topoheight, keep_last)
    }
}