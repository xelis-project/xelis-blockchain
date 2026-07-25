use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractProvider, MemoryStorage},
};

#[async_trait]
impl VersionedContractProvider for MemoryStorage {
    async fn delete_versioned_contracts_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.modules.split_off(&topoheight);
            });
        Ok(())
    }

    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let topoheight = topoheight + 1;
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.modules.split_off(&topoheight);
            });
        Ok(())
    }

    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                Self::delete_versioned_data_below_topoheight(&mut entry.modules, topoheight, keep_last);
            });

        Ok(())
    }
}
