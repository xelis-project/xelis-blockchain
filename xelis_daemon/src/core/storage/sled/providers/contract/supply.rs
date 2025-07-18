use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{SledStorage, SupplyProvider, VersionedSupply}
};

#[async_trait]
impl SupplyProvider for SledStorage {
    async fn get_asset_supply_at_maximum_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError> {
        trace!("get asset {} supply at maximum topoheight {}", asset, topoheight);

        let mut topo = if self.has_asset_supply_at_exact_topoheight(asset, topoheight).await? {
            Some(topoheight)
        } else if self.has_supply_for_asset(asset).await? {
            self.load_optional_from_disk(&self.assets_supply, asset.as_bytes())?
        } else {
            None
        };

        while let Some(t) = topo {
            if t <= topoheight {
                let supply = self.load_from_disk(
                    &self.versioned_assets_supply,
                    &Self::get_versioned_key(asset, t),
                    DiskContext::AssetSupplyAtTopoHeight(topoheight)
                )?;

                return Ok(Some((t, supply)));
            }

            topo = self.load_from_disk(&self.versioned_assets_supply, &Self::get_versioned_key(asset, topoheight), DiskContext::AssetSupplyTopoHeight)?;
        }

        Ok(None)
    }

    async fn has_asset_supply_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has asset {} supply at exact topoheight {}", asset, topoheight);
        self.contains_data(&self.versioned_assets_supply, &Self::get_versioned_key(asset, topoheight))
    }

    async fn has_supply_for_asset(&self, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("has supply for asset {}", asset);
        self.contains_data(&self.assets_supply, asset)
    }

    async fn set_last_supply_for_asset(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError> {
        trace!("set last supply for asset {} at topoheight {}", asset, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_assets_supply, &Self::get_versioned_key(asset, topoheight), supply.to_bytes())?;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.assets_supply, asset, &topoheight.to_be_bytes())?;

        Ok(())
    }

}