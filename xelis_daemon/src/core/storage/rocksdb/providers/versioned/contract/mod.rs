mod data;
mod balance;
mod supply;

use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{error::BlockchainError, storage::{RocksStorage, VersionedContractProvider}};

#[async_trait]
impl VersionedContractProvider for RocksStorage {
    // delete versioned contracts at topoheight
    async fn delete_versioned_contracts_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    // delete versioned contracts above topoheight
    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // delete versioned contracts below topoheight
    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        todo!()
    }
}