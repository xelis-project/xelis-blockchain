use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractDataProvider, MemoryStorage},
};

#[async_trait]
impl VersionedContractDataProvider for MemoryStorage {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.data.retain(|_, data_map| {
                    data_map.split_off(&topoheight);
                    !data_map.is_empty()
                });
            });
        Ok(())
    }

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let topoheight = topoheight.saturating_add(1);
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.data.retain(|_, data_map| {
                    data_map.split_off(&topoheight);
                    !data_map.is_empty()
                });
            });
        Ok(())
    }

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.data.retain(|_, data_map| {
                    MemoryStorage::delete_versioned_data_below_topoheight(data_map, topoheight, keep_last);
                    !data_map.is_empty()
                });
            });
        Ok(())
    }
}
