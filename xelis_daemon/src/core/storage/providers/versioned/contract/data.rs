use async_trait::async_trait;
use log::trace;
use xelis_common::{block::TopoHeight, serializer::Serializer};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{SledStorage, VersionedContractData}
};

#[async_trait]
pub trait VersionedContractDataProvider {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedContractDataProvider for SledStorage {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts data at topoheight {}", topoheight);
        for el in self.versioned_contracts_data.scan_prefix(&topoheight.to_be_bytes()) {
            let (key, value) = el?;
            // Delete this version from DB
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.versioned_contracts_data, &key)?;

            // Deserialize keys part
            let key_pointer = &key[8..];

            // Because of chain reorg, it may have been already deleted
            if let Some(last_topoheight) = self.load_optional_from_disk::<TopoHeight>(&self.contracts_data, key_pointer)? {
                if last_topoheight >= topoheight {
                    // Deserialize value, it is needed to get the previous topoheight
                    let version = VersionedContractData::from_bytes(&value)?;
                    // Now records changes
                    if let Some(previous_topoheight) = version.get_previous_topoheight() {
                        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_data, key_pointer, &previous_topoheight.to_be_bytes())?;
                    } else {
                        // if there is no previous topoheight, it means that this is the first version
                        // so we can delete the balance
                        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.contracts_data, key_pointer)?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts data above topoheight {}", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.versioned_contracts_data, topoheight)
    }

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts data below topoheight {}", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.contracts_data, &self.versioned_contracts_data, topoheight, keep_last, DiskContext::ContractDataAtTopoHeight)
    }
}