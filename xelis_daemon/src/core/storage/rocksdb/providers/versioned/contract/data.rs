use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{block::TopoHeight, serializer::RawBytes, versioned_type::Versioned};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, IteratorMode},
        RocksStorage,
        VersionedContractDataProvider
    }
};

#[async_trait]
impl VersionedContractDataProvider for RocksStorage {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let prefix = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedContractsData)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsData, &key)?;
            let pointer = self.load_optional_from_disk::<_, TopoHeight>(Column::ContractsData, &key[8..])?;

            if let Some(pointer) = pointer {
                if pointer >= topoheight {
                    if let Some(prev_topo) = prev_topo {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::ContractsData, &key[8..], &prev_topo.to_be_bytes())?;
                    } else {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::ContractsData, &key[8..])?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let start = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContractsData)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsData, &key)?;
            let pointer = self.load_optional_from_disk::<_, TopoHeight>(Column::ContractsData, &key[8..])?;
            if pointer.is_none_or(|v| v > topoheight) {
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != pointer {
                    if let Some(pointer) = filtered {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::ContractsData, &key[8..], &pointer.to_be_bytes())?;
                    } else {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::ContractsData, &key[8..])?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        let start = topoheight.to_be_bytes();
        if keep_last {
            for res in Self::iter_owned_internal::<RawBytes, TopoHeight>(&self.db, self.snapshot.as_ref(), IteratorMode::Start, Column::ContractsData)? {
                let (key, pointer) = res?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                let mut prev_version = Some(pointer);
                // If we are already below the threshold, we can directly erase without patching
                let mut patched = pointer < topoheight;

                // Craft by hand the key
                let mut versioned_key = vec![0; 24];
                versioned_key[8..].copy_from_slice(&key);
                
                while let Some(prev_topo) = prev_version {
                    versioned_key[0..8].copy_from_slice(&prev_topo.to_be_bytes());

                    // Delete this version from DB if its below the threshold
                    prev_version = self.load_from_disk(Column::VersionedContractsData, &versioned_key)?;
                    if patched {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsData, &versioned_key)?;
                    } else {
                        if prev_version.is_some_and(|v| v < topoheight) {
                            trace!("Patching versioned data at topoheight {}", topoheight);
                            patched = true;
                            let mut data: Versioned<RawBytes> = self.load_from_disk(Column::VersionedContractsData, &versioned_key)?;
                            data.set_previous_topoheight(None);

                            Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsData, &versioned_key, &data)?;
                        }
                    }
                }
            }
        } else {
            for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContractsData)? {
                let (key, _) = res?;
                Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsData, &key)?;
            }
        }

        Ok(())
    }
}