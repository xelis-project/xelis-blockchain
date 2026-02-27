use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::VersionedAssetsCirculatingSupplyProvider,
};
use super::super::super::MemoryStorage;

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
            .for_each(|(_, entry)| {
                let mut to_keep = entry.supply.split_off(&topoheight);
                to_keep.first_entry()
                    .map(|mut entry| {
                        entry.get_mut()
                            .set_previous_topoheight(None);
                    });

                entry.supply = to_keep;
            });

        Ok(())
    }
}
