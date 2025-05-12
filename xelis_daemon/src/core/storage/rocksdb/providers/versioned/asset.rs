use async_trait::async_trait;
use xelis_common::{block::TopoHeight, serializer::RawBytes};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        RocksStorage,
        VersionedAssetProvider
    }
};

#[async_trait]
impl VersionedAssetProvider for RocksStorage {
    // delete versioned assets at topoheight
    async fn delete_versioned_assets_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>, _>(&self.db, self.snapshot.as_ref(), Some(topoheight.to_be_bytes()), Column::VersionedAssets)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedAssets, &key)?;
            // TODO: asset by id
            let key_without_prefix = &key[8..];
            if let Some(pointer) = Self::load_optional_from_disk_internal::<_, TopoHeight>(&self.db, self.snapshot.as_ref(), Column::Assets, key_without_prefix)? {
                if pointer >= topoheight {
                    if let Some(prev_topo) = prev_topo {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Assets, key_without_prefix, &prev_topo.to_be_bytes())?;
                    } else {
                        // No previous topoheight, we can delete the balance
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::Assets, &key_without_prefix)?;
                    }
                }
            }
        }

        Ok(())
    }

    // delete versioned assets above topoheight
    async fn delete_versioned_assets_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // delete versioned assets below topoheight
    async fn delete_versioned_assets_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        todo!()
    }
}