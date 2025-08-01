use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{
    block::TopoHeight,
    serializer::{RawBytes, Serializer}, versioned_type::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Asset, AssetId, Column, IteratorMode},
        RocksStorage,
        VersionedAssetsSupplyProvider
    }
};

#[async_trait]
impl VersionedAssetsSupplyProvider for RocksStorage {
    async fn delete_versioned_assets_supply_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned assets supply at topoheight {}", topoheight);
        let prefix = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedAssetsSupply)? {
            let (versioned_key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssetsSupply, &versioned_key)?;

            let key_without_prefix = &versioned_key[8..];
            
            let asset_id = AssetId::from_bytes(&key_without_prefix[0..8])?;
            let asset_hash = self.get_asset_hash_from_id(asset_id)?;
            let mut asset = self.get_asset_type(&asset_hash)?;

            if asset.supply_pointer.is_none_or(|pointer| pointer >= topoheight) {
                asset.supply_pointer = prev_topo;

                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Assets, &asset_hash, &asset)?;
            }
        }

        Ok(())
    }

    async fn delete_versioned_assets_supply_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned assets supply above topoheight {}", topoheight);
        let start = (topoheight + 1).to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedAssetsSupply)? {
            let (key, prev_topo) = res?;
            // Delete the version we've read
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssetsSupply, &key)?;

            let asset_id = AssetId::from_bytes(&key[8..16])?;
            let hash = self.get_asset_hash_from_id(asset_id)?;
            let mut asset = self.get_asset_type(&hash)?;

            // This algorithm should be finding the latest valid pointer
            // while limiting updates, it will write the highest
            // pointer if any, or set to None

            // Case 1: pointer is above topoheight => we update it
            // Case 2: pointer is None => we update it
            if asset.supply_pointer.is_none_or(|v| v > topoheight) {
                // Case 1: prev topo is below or equal to requested topoheight => update it
                // Case 2: prev topo is None but pointer is Some => we update it
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != asset.supply_pointer {
                    asset.supply_pointer = filtered;
                    Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Assets, &hash, &asset)?;
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_assets_supply_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned assets below topoheight {}", topoheight);
        if keep_last {
            for res in Self::iter_owned_internal::<(), Asset>(&self.db, self.snapshot.as_ref(), IteratorMode::Start, Column::Assets)? {
                let (_, asset) = res?;

                if let Some(topo) = asset.data_pointer {
                    // We fetch the last version to take its previous topoheight
                    // And we loop on it to delete them all until the end of the chained data
                    let mut prev_version = Some(topo);
                    // If we are already below the threshold, we can directly erase without patching
                    let mut patched = topo < topoheight;
                    while let Some(prev_topo) = prev_version {
                        let key = Self::get_asset_versioned_key(asset.id, prev_topo);
    
                        // Delete this version from DB if its below the threshold
                        prev_version = self.load_from_disk(Column::VersionedAssetsSupply, &key)?;
                        if patched {
                            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssetsSupply, &key)?;
                        } else {
                            if prev_version.is_some_and(|v| v < topoheight) {
                                trace!("Patching versioned data at topoheight {}", topoheight);
                                patched = true;
                                let mut data: Versioned<RawBytes> = self.load_from_disk(Column::VersionedAssetsSupply, &key)?;
                                data.set_previous_topoheight(None);

                                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssetsSupply, &key, &data)?;
                            }
                        }
                    }
                }
            }
        } else {
            let start = topoheight.to_be_bytes();
            for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Reverse), Column::VersionedAssetsSupply)? {
                let (key, _) = res?;
                Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssetsSupply, &key)?;
            }
        }

        Ok(())
    }
}