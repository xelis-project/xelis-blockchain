use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use log::trace;

use crate::core::{
    error::BlockchainError,
    storage::{RocksStorage, VersionedContractEventCallbackProvider, rocksdb::Column}
};

#[async_trait]
impl VersionedContractEventCallbackProvider for RocksStorage {
    // delete versioned contract event callbacks at topoheight
    async fn delete_versioned_contract_event_callbacks_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contract event callbacks at topoheight {}", topoheight);
        self.delete_versioned_at_topoheight(Column::ContractEventCallbacks, Column::VersionedContractEventCallbacks, topoheight).await
    }

    // delete versioned contract event callbacks above topoheight
    async fn delete_versioned_contract_event_callbacks_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contract event callbacks above topoheight {}", topoheight);
        self.delete_versioned_above_topoheight(Column::ContractEventCallbacks, Column::VersionedContractEventCallbacks, topoheight).await
    }

    // delete versioned contract event callbacks below topoheight
    async fn delete_versioned_contract_event_callbacks_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contract event callbacks below topoheight {}", topoheight);
        self.delete_versioned_below_topoheight_default(Column::ContractEventCallbacks, Column::VersionedContractEventCallbacks, topoheight, keep_last).await
    }
}