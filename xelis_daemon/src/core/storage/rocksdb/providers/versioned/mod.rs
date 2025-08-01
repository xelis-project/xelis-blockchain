use rocksdb::Direction;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    serializer::RawBytes,
    versioned_type::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, IteratorMode},
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

impl VersionedProvider for RocksStorage {}

impl RocksStorage {
    pub fn delete_versioned_at_topoheight(&mut self, column_pointer: Column, column_versioned: Column, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let prefix = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), column_versioned)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_versioned, &key)?;
            let pointer = self.load_optional_from_disk::<_, TopoHeight>(column_pointer, &key[8..])?;

            if let Some(pointer) = pointer {
                if pointer >= topoheight {
                    if let Some(prev_topo) = prev_topo {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), column_pointer, &key[8..], &prev_topo.to_be_bytes())?;
                    } else {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_pointer, &key[8..])?;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn delete_versioned_above_topoheight(&mut self, column_pointer: Column, column_versioned: Column, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let start = (topoheight + 1).to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), column_versioned)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_versioned, &key)?;
            let pointer = self.load_optional_from_disk::<_, TopoHeight>(column_pointer, &key[8..])?;
            if pointer.is_none_or(|v| v > topoheight) {
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

    pub fn delete_versioned_below_topoheight(&mut self, column_pointer: Column, column_versioned: Column, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        if keep_last {
            for res in Self::iter_owned_internal::<RawBytes, TopoHeight>(&self.db, self.snapshot.as_ref(), IteratorMode::Start, column_pointer)? {
                let (key, pointer) = res?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                let mut prev_version = Some(pointer);
                // If we are already below the threshold, we can directly erase without patching
                let mut patched = pointer < topoheight;

                // Craft by hand the key
                let mut versioned_key = vec![0; key.len() + 8];
                versioned_key[8..].copy_from_slice(&key);
                
                while let Some(prev_topo) = prev_version {
                    versioned_key[0..8].copy_from_slice(&prev_topo.to_be_bytes());

                    // Delete this version from DB if its below the threshold
                    prev_version = self.load_from_disk(column_versioned, &versioned_key)?;
                    if patched {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column_versioned, &versioned_key)?;
                    } else if prev_version.is_some_and(|v| v < topoheight) {
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
        for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Reverse), column)? {
            let (key, _) = res?;
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column, &key)?;
        }

        Ok(())
    }
}