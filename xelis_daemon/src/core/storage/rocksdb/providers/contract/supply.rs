use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    versioned_type::Versioned
};
use crate::core::{error::BlockchainError, storage::{rocksdb::Column, RocksStorage, SupplyProvider}};

pub type VersionedSupply = Versioned<u64>;

#[async_trait]
impl SupplyProvider for RocksStorage {
    // Verify if we have a supply already set for this asset
    async fn has_supply_for_asset(&self, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("has supply for asset {}", asset);
        let Some(asset) = self.get_optional_asset_type(asset)? else {
            return Ok(false)
        };
        Ok(asset.supply_pointer.is_some())
    }

    // Verify if we have a versioned data at exact topoheight
    async fn has_asset_supply_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has asset {} supply at exact topoheight {}", asset, topoheight);
        let asset_id = self.get_asset_id(asset)?;
        let key = Self::get_asset_versioned_key(asset_id, topoheight);
        self.contains_data(Column::VersionedAssetsSupply, &key)
    }

    // Get the supply at the maximum topoheight
    async fn get_asset_supply_at_maximum_topoheight(&self, asset: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError> {
        trace!("get asset {} supply at maximum topoheight {}", asset, maximum_topoheight);
        let Some(asset) = self.get_optional_asset_type(asset)? else {
            return Ok(None)
        };
        let Some(pointer) = asset.supply_pointer else {
            return Ok(None)
        };

        let versioned_key = Self::get_asset_versioned_key(maximum_topoheight, asset.id);
        let mut prev_topo = if pointer > maximum_topoheight && self.contains_data(Column::VersionedAssetsSupply, &versioned_key)? {
            Some(self.load_from_disk(Column::VersionedAssetsSupply, &versioned_key)?)
        } else {
            Some(pointer)
        };

        while let Some(topo) = prev_topo {
            let versioned_key = Self::get_asset_versioned_key(topo, asset.id);
            if topo <= maximum_topoheight {
                let version = self.load_from_disk(Column::VersionedAssetsSupply, &versioned_key)?;
                return Ok(Some((topo, version)))
            }

            prev_topo = self.load_from_disk(Column::VersionedAssetsSupply, &versioned_key)?;
        }

        Ok(None)
    }

    // Set the latest supply pointer for this asset and store the versioned data
    async fn set_last_supply_for_asset(&mut self, hash: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError> {
        trace!("set last supply for asset {} at topoheight {}", hash, topoheight);
        let mut asset = self.get_asset_type(hash)?;
        asset.supply_pointer = Some(topoheight);

        let versioned_key = Self::get_asset_versioned_key(topoheight, asset.id);
        self.insert_into_disk(Column::VersionedAssetsSupply, &versioned_key, supply)?;
        self.insert_into_disk(Column::Assets, hash, &asset)
    }
}