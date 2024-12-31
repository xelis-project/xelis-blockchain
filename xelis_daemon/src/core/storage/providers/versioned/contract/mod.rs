mod data;
mod balance;

use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{ContractProvider, SledStorage, VersionedContract}
};

pub use data::*;
pub use balance::*;

#[async_trait]
pub trait VersionedContractProvider {
    // delete versioned contracts at topoheight
    async fn delete_versioned_contracts_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned contracts above topoheight
    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned contracts below topoheight
    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedContractProvider for SledStorage {
    async fn delete_versioned_contracts_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts at topoheight {}", topoheight);
        for el in self.versioned_contracts.scan_prefix(&topoheight.to_be_bytes()) {
            let (key, value) = el?;
            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_contracts, &key)?;

            // Deserialize keys part
            let key = Hash::from_bytes(&key[8..])?;

            // Because of chain reorg, it may have been already deleted
            if let Ok(last_topoheight) = self.get_last_topoheight_for_contract(&key).await {
                if last_topoheight >= topoheight {
                    // Deserialize value, it is needed to get the previous topoheight
                    let version = VersionedContract::from_bytes(&value)?;
                    // Now records changes
                    if let Some(previous_topoheight) = version.get_previous_topoheight() {
                        self.set_last_topoheight_for_contract(&key, previous_topoheight).await?;
                    } else {
                        // if there is no previous topoheight, it means that this is the first version
                        // so we can delete the balance
                        self.delete_last_topoheight_for_contract(&key).await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts above topoheight {}!", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.versioned_contracts, topoheight)
    }

    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: u64, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts below topoheight {}!", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.contracts, &self.versioned_contracts, topoheight, keep_last, DiskContext::ContractAtTopoHeight)
    }
}