use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{
    block::TopoHeight,
    serializer::RawBytes,
    versioned_type::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            AssetId,
            Column,
            ContractId,
            IteratorMode
        },
        RocksStorage,
        VersionedContractBalanceProvider
    }
};

#[async_trait]
impl VersionedContractBalanceProvider for RocksStorage {
    async fn delete_versioned_contract_balances_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let prefix = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedContractsBalances)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsBalances, &key)?;
            let pointer = self.load_optional_from_disk::<_, TopoHeight>(Column::ContractsBalances, &key[8..])?;

            if let Some(pointer) = pointer {
                if pointer >= topoheight {
                    if let Some(prev_topo) = prev_topo {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::ContractsBalances, &key[8..], &prev_topo.to_be_bytes())?;
                    } else {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::ContractsBalances, &key[8..])?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_contract_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let start = topoheight.to_be_bytes();

        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContractsBalances)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsBalances, &key)?;
            let pointer = self.load_optional_from_disk::<_, TopoHeight>(Column::ContractsBalances, &key[8..])?;
            if pointer.is_none_or(|v| v > topoheight) {
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != pointer {
                    if let Some(pointer) = filtered {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::ContractsBalances, &key[8..], &pointer.to_be_bytes())?;
                    } else {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::ContractsBalances, &key[8..])?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_contract_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        let start = topoheight.to_be_bytes();
        if keep_last {
            for res in Self::iter_owned_internal::<(ContractId, AssetId), TopoHeight>(&self.db, self.snapshot.as_ref(), IteratorMode::Start, Column::ContractsBalances)? {
                let ((contract_id, asset_id), pointer) = res?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                let mut prev_version = Some(pointer);
                // If we are already below the threshold, we can directly erase without patching
                let mut patched = pointer < topoheight;
                while let Some(prev_topo) = prev_version {
                    let key = Self::get_versioned_contract_balance_key(contract_id, asset_id, prev_topo);

                    // Delete this version from DB if its below the threshold
                    prev_version = self.load_from_disk(Column::VersionedContractsBalances, &key)?;
                    if patched {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsBalances, &key)?;
                    } else {
                        if prev_version.is_some_and(|v| v < topoheight) {
                            trace!("Patching versioned data at topoheight {}", topoheight);
                            patched = true;
                            let mut data: Versioned<RawBytes> = self.load_from_disk(Column::VersionedContractsBalances, &key)?;
                            data.set_previous_topoheight(None);

                            Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsBalances, &key, &data)?;
                        }
                    }
                }
            }
        } else {
            for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedContractsBalances)? {
                let (key, _) = res?;
                Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedContractsBalances, &key)?;
            }
        }

        Ok(())
    }
}