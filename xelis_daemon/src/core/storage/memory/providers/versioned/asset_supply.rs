use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedAssetsCirculatingSupplyProvider, MemoryStorage},
};

#[async_trait]
impl VersionedAssetsCirculatingSupplyProvider for MemoryStorage {
    async fn delete_versioned_assets_supply_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.assets.iter_mut().for_each(|(_, entry)| {
            entry.supply.split_off(&topoheight);
        });

        Ok(())
    }

    async fn delete_versioned_assets_supply_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.assets.iter_mut().for_each(|(_, entry)| {
            entry.supply.split_off(&(topoheight + 1));
        });

        Ok(())
    }

    async fn delete_versioned_assets_supply_below_topoheight(&mut self, topoheight: TopoHeight, _keep_last: bool) -> Result<(), BlockchainError> {
        self.assets.iter_mut()
            .for_each(|(_, entry)| Self::delete_versioned_data_below_topoheight(&mut entry.supply, topoheight, true));

        Ok(())
    }
}
