use log::trace;
use xelis_common::{
    block::TopoHeight,
    serializer::{RawBytes, Serializer},
    versioned_type::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, IteratorMode},
        snapshot::{BytesView, Direction},
        RocksStorage,
        VersionedProvider
    }
};

mod balance;
mod contract;
mod multisig;
mod nonce;
mod registrations;
mod asset;
mod cache;
mod dag_order;
mod asset_supply;

impl VersionedProvider for RocksStorage {}

impl RocksStorage {
    pub fn delete_versioned_at_topoheight(&mut self, column_pointer: Column, column_versioned: Column, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let prefix = topoheight.to_be_bytes();
        let snapshot = self.snapshot.clone();
        for res in Self::iter_raw_internal(&self.db, snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), column_versioned)? {
            let (key, value) = res?;

            // Delete this version from DB
            // We read the previous topoheight to check if we need to update the pointer
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_versioned, &key)?;

            // Key without the topoheight
            let key_without_topo = &key[8..];
            let pointer = self.load_optional_from_disk::<_, TopoHeight>(column_pointer, key_without_topo)?;

            if pointer.is_some_and(|pointer| pointer >= topoheight) {
                let prev_topo = Option::<TopoHeight>::from_bytes(&value)?;
                if let Some(prev_topo) = prev_topo {
                    Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), column_pointer, key_without_topo, &prev_topo.to_be_bytes())?;
                } else {
                    // No previous topoheight, we can delete the pointer
                    Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_pointer, key_without_topo)?;
                }
            }
        }

        Ok(())
    }

    pub fn delete_versioned_above_topoheight(&mut self, column_pointer: Column, column_versioned: Column, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let start = (topoheight + 1).to_be_bytes();
        let snapshot = self.snapshot.clone();
        for res in Self::iter_raw_internal(&self.db, snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), column_versioned)? {
            let (key, value) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_versioned, &key)?;
            let pointer = self.load_optional_from_disk::<_, TopoHeight>(column_pointer, &key[8..])?;
            if pointer.is_none_or(|v| v > topoheight) {
                let prev_topo = Option::<TopoHeight>::from_bytes(&value)?;
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != pointer {
                    if let Some(pointer) = filtered {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), column_pointer, &key[8..], &pointer.to_be_bytes())?;
                    } else {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_pointer, &key[8..])?;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn delete_versioned_below_topoheight_default(
        &mut self,
        column_pointer: Column,
        column_versioned: Column,
        topoheight: TopoHeight,
        keep_last: bool,
    ) -> Result<(), BlockchainError> {
        self.delete_versioned_below_topoheight(column_pointer, column_versioned, topoheight, keep_last, |k, v| Ok((RawBytes::from_bytes(&k)?, v)))
    }

    pub fn delete_versioned_below_topoheight<V: Serializer, K: Serializer>(
        &mut self,
        column_pointer: Column,
        column_versioned: Column,
        topoheight: TopoHeight,
        keep_last: bool,
        mut mapper: impl FnMut(BytesView<'_>, V) -> Result<(K, Option<TopoHeight>), BlockchainError>,
    ) -> Result<(), BlockchainError> {
        if keep_last {
            let snapshot = self.snapshot.clone();
            for res in Self::iter_raw_internal(&self.db, snapshot.as_ref(), IteratorMode::Start, column_pointer)? {
                let (key, value) = res?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                let pointer = V::from_bytes(&value)?;
                let (mapped_key, mut prev_version) = mapper(key, pointer)?;
                // If we are already below the threshold, we can directly erase without patching
                let mut patched = false;

                // Craft by hand the key
                let bytes = mapped_key.to_bytes();
                let mut versioned_key = vec![0; bytes.len() + 8];
                versioned_key[8..].copy_from_slice(&bytes);

                trace!("pointer detected is {:?}", prev_version);
                while let Some(prev_topo) = prev_version.take() {
                    trace!("loading versioned data at topoheight {}", prev_topo);

                    versioned_key[0..8].copy_from_slice(&prev_topo.to_be_bytes());

                    // Fetch the previous version before potentially deleting it
                    prev_version = self.load_from_disk(column_versioned, &versioned_key)?;
                    if patched {
                        trace!("deleting versioned data at topoheight {}", prev_topo);
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_versioned, &versioned_key)?;
                    } else if prev_topo < topoheight {
                        trace!("Patching versioned data at topoheight {}", topoheight);
                        patched = true;

                        let mut data: Versioned<RawBytes> = self.load_from_disk(column_versioned, &versioned_key)?;
                        data.set_previous_topoheight(None);

                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), column_versioned, &versioned_key, &data)?;
                    }
                }
            }

            Ok(())
        } else {
            self.delete_versioned_data_below_topoheight(column_versioned, topoheight)
        }
    }

    fn delete_versioned_data_below_topoheight(&mut self, column: Column, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let start = topoheight.to_be_bytes();
        let snapshot = self.snapshot.clone();
        for res in Self::iter_raw_internal(&self.db, snapshot.as_ref(), IteratorMode::From(&start, Direction::Reverse), column)? {
            let (key, _) = res?;
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column, &key)?;
        }

        Ok(())
    }
}