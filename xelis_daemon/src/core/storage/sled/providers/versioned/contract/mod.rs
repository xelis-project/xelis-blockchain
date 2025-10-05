mod data;
mod balance;
mod delayed_execution;

use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{SledStorage, VersionedContractProvider}
};

#[async_trait]
impl VersionedContractProvider for SledStorage {
    async fn delete_versioned_contracts_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts at topoheight {}", topoheight);
        Self::delete_versioned_tree_at_topoheight(&mut self.snapshot, &self.contracts, &self.versioned_contracts, topoheight)
    }

    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts above topoheight {}!", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.contracts, &self.versioned_contracts, topoheight, DiskContext::VersionedContract)
    }

    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: u64, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts below topoheight {}!", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.contracts, &self.versioned_contracts, topoheight, keep_last, DiskContext::VersionedContract)
    }
}