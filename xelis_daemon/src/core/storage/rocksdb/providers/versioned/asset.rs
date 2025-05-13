use async_trait::async_trait;
use rocksdb::Direction;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    serializer::{RawBytes, Serializer},
    versioned_type::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            Asset,
            AssetId,
            Column,
            IteratorMode
        },
        RocksStorage,
        VersionedAssetProvider
    }
};

#[async_trait]
impl VersionedAssetProvider for RocksStorage {
    // delete versioned assets at topoheight
    async fn delete_versioned_assets_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let prefix = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedAssets)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssets, &key)?;

            let key_without_prefix = &key[8..];
            let asset_id = AssetId::from_bytes(&key_without_prefix[0..8])?;
            let asset_hash = self.get_asset_hash_from_id(asset_id)?;
            let mut asset = self.get_asset_type(&asset_hash)?;

            if let Some(pointer) = Self::load_optional_from_disk_internal::<_, TopoHeight>(&self.db, self.snapshot.as_ref(), Column::Assets, key_without_prefix)? {
                if pointer >= topoheight {
                    if let Some(prev_topo) = prev_topo {
                        asset.data_pointer = Some(prev_topo);
                    } else {
                        asset.data_pointer = None;                        
                    }

                    Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Assets, &asset_hash, &asset)?;
                }
            }
        }

        Ok(())
    }

    // delete versioned assets above topoheight
    async fn delete_versioned_assets_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let start = (topoheight + 1).to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedAssets)? {
            let (key, prev_topo) = res?;
            // Delete the version we've read
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssets, &key)?;

            let asset_id = AssetId::from_bytes(&key[8..16])?;
            let hash = self.get_asset_hash_from_id(asset_id)?;
            let mut asset = self.get_asset_type(&hash)?;

            // This algorithm should be finding the latest valid data pointer
            // while limiting updates, it will write the highest
            // data pointer if any, or set to None

            // Case 1: data pointer is above topoheight => we update it
            // Case 2: data pointer is None => we update it
            if asset.data_pointer.is_none_or(|v| v > topoheight) {
                // Case 1: prev topo is below or equal to requested topoheight => update it
                // Case 2: prev topo is None but pointer is Some => we update it
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != asset.data_pointer {
                    asset.data_pointer = filtered;
                    Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Assets, &hash, &asset)?;
                }
            }
        }

        Ok(())
    }

    // delete versioned assets below topoheight
    async fn delete_versioned_assets_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        let start = topoheight.to_be_bytes();
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
                        let key = Self::create_asset_versioned_key(asset.id, prev_topo);
    
                        // Delete this version from DB if its below the threshold
                        prev_version = self.load_from_disk(Column::VersionedAssets, &key)?;
                        if patched {
                            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssets, &key)?;
                        } else {
                            if prev_version.is_some_and(|v| v < topoheight) {
                                trace!("Patching versioned data at topoheight {}", topoheight);
                                patched = true;
                                let mut data: Versioned<RawBytes> = self.load_from_disk(Column::VersionedAssets, &key)?;
                                data.set_previous_topoheight(None);

                                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssets, &key, &data)?;
                            }
                        }
                    }
                }
            }
        } else {
            for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedAssets)? {
                let (key, _) = res?;
                Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssets, &key)?;
            }
        }

        Ok(())
    }
}