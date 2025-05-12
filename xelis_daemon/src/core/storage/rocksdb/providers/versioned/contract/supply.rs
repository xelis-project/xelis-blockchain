use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{error::BlockchainError, storage::{RocksStorage, VersionedSupplyProvider}};

#[async_trait]
impl VersionedSupplyProvider for RocksStorage {
    async fn delete_versioned_assets_supply_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn delete_versioned_assets_supply_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    async fn delete_versioned_assets_supply_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        todo!()
    }
}