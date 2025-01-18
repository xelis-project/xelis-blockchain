use async_trait::async_trait;
use log::trace;
use xelis_common::{block::TopoHeight, crypto::Hash, serializer::Serializer, versioned_type::Versioned};
use crate::core::{error::{BlockchainError, DiskContext}, storage::SledStorage};

pub type VersionedSupply = Versioned<u64>;

#[async_trait]
pub trait SupplyProvider {
    // Verify if we have a supply already set for this asset
    async fn has_supply_for_asset(&self, asset: &Hash) -> Result<bool, BlockchainError>;

    // Verify if we have a versioned data at exact topoheight
    async fn has_asset_supply_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the latest supply topoheight for asset
    async fn get_last_topoheight_for_asset_supply(&self, asset: &Hash) -> Result<TopoHeight, BlockchainError>;

    // Get a versioned supply at a specific topoheight
    async fn get_asset_supply_at_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedSupply, BlockchainError>;

    // Get the supply at the maximum topoheight
    async fn get_asset_supply_at_maximum_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError>;

    // Set the latest supply pointer for this asset and store the versioned data
    async fn set_last_supply_for_asset(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError>;

    // Set the topoheight as last pointer for the asset supply
    async fn set_last_topoheight_for_asset_supply(&mut self, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Store the versioned supply to a specific topoheight
    async fn set_asset_supply_at_topoheight(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError>;
}

#[async_trait]
impl SupplyProvider for SledStorage {
    async fn get_asset_supply_at_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedSupply, BlockchainError> {
        trace!("get asset {} supply at topoheight {}", asset, topoheight);
        self.load_from_disk(&self.versioned_assets_supply, &Self::get_versioned_key(asset, topoheight), DiskContext::AssetSupplyAtTopoHeight)
    }

    async fn get_last_topoheight_for_asset_supply(&self, asset: &Hash) -> Result<TopoHeight, BlockchainError> {
        trace!("get last topoheight for asset {} supply", asset);
        self.load_from_disk(&self.assets_supply, asset.as_bytes(), DiskContext::AssetSupplyTopoHeight)
    }

    async fn get_asset_supply_at_maximum_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError> {
        trace!("get asset {} supply at maximum topoheight {}", asset, topoheight);

        let mut topo = if self.has_asset_supply_at_exact_topoheight(asset, topoheight).await? {
            Some(topoheight)
        } else if self.has_supply_for_asset(asset).await? {
            Some(self.get_last_topoheight_for_asset_supply(asset).await?)
        } else {
            None
        };

        while let Some(t) = topo {
            if t < topoheight {
                let supply = self.get_asset_supply_at_topoheight(asset, t).await?;
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

    async fn set_asset_supply_at_topoheight(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError> {
        trace!("set asset {} supply at topoheight {}", asset, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_assets_supply, &Self::get_versioned_key(asset, topoheight), supply.to_bytes())?;
        Ok(())
    }

    async fn set_last_supply_for_asset(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError> {
        trace!("set last supply for asset {} at topoheight {}", asset, topoheight);
        self.set_asset_supply_at_topoheight(asset, topoheight, supply).await?;
        self.set_last_topoheight_for_asset_supply(asset, topoheight).await?;

        Ok(())
    }

    async fn set_last_topoheight_for_asset_supply(&mut self, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set last topoheight for asset {} supply to {}", asset, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.assets_supply, asset, &topoheight.to_be_bytes())?;
        Ok(())
    }
}