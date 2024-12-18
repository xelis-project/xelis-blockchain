use async_trait::async_trait;
use log::trace;
use xelis_common::{block::TopoHeight, crypto::Hash, serializer::Serializer};
use crate::core::{
    error::BlockchainError,
    storage::{ContractDataProvider, SledStorage, VersionedContractData}
};

#[async_trait]
pub trait VersionedContractDataProvider {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
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
            let key = Hash::from_bytes(&key[8..])?;

            // Because of chain reorg, it may have been already deleted
            if let Ok(last_topoheight) = self.get_last_topoheight_for_contract_data(&key).await {
                if last_topoheight >= topoheight {
                    // Deserialize value, it is needed to get the previous topoheight
                    let version = VersionedContractData::from_bytes(&value)?;
                    // Now records changes
                    if let Some(previous_topoheight) = version.get_previous_topoheight() {
                        self.set_last_topoheight_for_contract_data(&key, previous_topoheight).await?;
                    } else {
                        // if there is no previous topoheight, it means that this is the first version
                        // so we can delete the balance
                        self.delete_last_topoheight_for_contract_data(&key).await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.versioned_contracts_data, topoheight)
    }

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.versioned_contracts_data, topoheight)
    }
}