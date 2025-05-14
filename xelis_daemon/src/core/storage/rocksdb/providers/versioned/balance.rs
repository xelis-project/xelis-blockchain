use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{
    account::BalanceType,
    block::TopoHeight,
    crypto::PublicKey,
    serializer::RawBytes
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            AccountId,
            AssetId,
            Column,
            IteratorMode
        },
        RocksStorage,
        VersionedBalanceProvider
    }
};

#[async_trait]
impl VersionedBalanceProvider for RocksStorage {
    // delete versioned balances at topoheight
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned balances at {}", topoheight);
        let prefix = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedBalances)? {
            let (key, prev_topo) = res?;
            let k: PublicKey = self.load_from_disk(Column::AccountById, &key[8..16])?;
            trace!("delete versioned balance for {}", k.as_address(true));

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedBalances, &key)?;
        
            let key_without_prefix = &key[8..];
            if let Some(pointer) = Self::load_optional_from_disk_internal::<_, TopoHeight>(&self.db, self.snapshot.as_ref(), Column::Balances, key_without_prefix)? {
                if pointer >= topoheight {
                    if let Some(prev_topo) = prev_topo {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Balances, key_without_prefix, &prev_topo.to_be_bytes())?;
                    } else {
                        // No previous topoheight, we can delete the balance
                        trace!("deleting balance for {}", k.as_address(true));
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::Balances, &key_without_prefix)?;
                    }
                }
            }
        }

        Ok(())
    }

    // delete versioned balances above topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let start = (topoheight + 1).to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedBalances)? {
            let (key, prev_topo) = res?;
            // Delete the version we've read
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedBalances, &key)?;

            let balance_pointer = self.load_optional_from_disk(Column::Balances, &key[8..])?;
            // This algorithm should be finding the latest valid data pointer
            // while limiting updates, it will write the highest
            // data pointer if any, or set to None

            // Case 1: data pointer is above topoheight => we update it
            // Case 2: data pointer is None => we update it
            if balance_pointer.is_none_or(|v| v > topoheight) {
                // Case 1: prev topo is below or equal to requested topoheight => update it
                // Case 2: prev topo is None but pointer is Some => we update it
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != balance_pointer {
                    if let Some(pointer) = filtered {
                        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Balances, &key[8..], &pointer.to_be_bytes())?;
                    } else {
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::Balances, &key[8..])?;
                    }
                }
            }
        }

        Ok(())
    }

    // delete versioned balances below topoheight
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        let start = topoheight.to_be_bytes();
        if keep_last {
            for res in Self::iter_owned_internal::<(AccountId, AssetId), TopoHeight>(&self.db, self.snapshot.as_ref(), IteratorMode::Start, Column::Balances)? {
                let ((account_id, asset_id), pointer) = res?;

                // We fetch the last version to take its previous topoheight
                // And we loop on it to delete them all until the end of the chained data
                // But before deleting, we need to find if we are below a output balance
                let mut prev_version = Some(pointer);
                let mut delete = false;
                while let Some(prev_topo) = prev_version {
                    let key = Self::get_versioned_account_balance_key(account_id, asset_id, prev_topo);

                    // Delete this version from DB if its below the threshold
                    if delete {
                        prev_version = self.load_from_disk(Column::VersionedBalances, &key)?;
                        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedBalances, &key)?;
                    } else {
                        let (prev_topo, ty) = self.load_from_disk::<_, (Option<u64>, BalanceType)>(Column::VersionedBalances, &key)?;
                        // If this version contains an output, that means we can delete all others below
                        delete = ty.contains_output();
                        prev_version = prev_topo;
                    }
                }
            }
        } else {
            for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedBalances)? {
                let (key, _) = res?;
                Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedBalances, &key)?;
            }
        }

        Ok(())
    }
}