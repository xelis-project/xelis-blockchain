use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        sled::PRUNED_TOPOHEIGHT,
        PrunedTopoheightProvider,
        RocksStorage,
    }
};

// This trait is used for pruning
#[async_trait]
impl PrunedTopoheightProvider for RocksStorage {
    // get the pruned topoheight
    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get pruned topoheight");
        self.load_optional_from_disk(Column::Common, PRUNED_TOPOHEIGHT)
    }

    // set the pruned topoheight on disk
    async fn set_pruned_topoheight(&mut self, pruned_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set pruned topoheight {}", pruned_topoheight);
        self.insert_into_disk(Column::Common, PRUNED_TOPOHEIGHT, &pruned_topoheight)
    }
}