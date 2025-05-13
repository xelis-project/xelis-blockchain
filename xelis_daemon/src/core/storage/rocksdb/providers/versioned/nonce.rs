use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{
    block::TopoHeight,
    serializer::{RawBytes, Serializer},
    versioned_type::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            Account,
            AccountId,
            Column,
            IteratorMode
        },
        NetworkProvider,
        RocksStorage,
        VersionedNonceProvider
    }
};

#[async_trait]
impl VersionedNonceProvider for RocksStorage {
    // delete versioned nonces at topoheight
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces at {}", topoheight);
        let prefix = topoheight.to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedNonces)? {
            let (key, prev_topo) = res?;

            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedNonces, &key)?;

            let key_without_prefix = &key[8..];
            let account_id = AccountId::from_bytes(&key_without_prefix[0..8])?;
            let account_key = self.get_account_key_from_id(account_id)?;
            let mut account = self.get_account_type(&account_key)?;

            if account.nonce_pointer.is_some_and(|pointer| pointer >= topoheight) {
                if let Some(prev_topo) = prev_topo {
                    account.nonce_pointer = Some(prev_topo);
                } else {
                    account.nonce_pointer = None;
                }

                trace!("updating account {} with nonce set to {:?}", account_key.as_address(self.is_mainnet()), account.nonce_pointer);
                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Account, account_key.as_bytes(), &account)?;
            }
        }

        Ok(())
    }

    // delete versioned nonces above topoheight
    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let start = (topoheight + 1).to_be_bytes();
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedNonces)? {
            let (key, prev_topo) = res?;
            // Delete the version we've read
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedNonces, &key)?;

            let account_id = AccountId::from_bytes(&key[8..16])?;
            let key = self.get_account_key_from_id(account_id)?;
            let mut account = self.get_account_type(&key)?;

            // This algorithm should be finding the latest valid data pointer
            // while limiting updates, it will write the highest
            // data pointer if any, or set to None

            // Case 1: data pointer is above topoheight => we update it
            // Case 2: data pointer is None => we update it
            if account.nonce_pointer.is_none_or(|v| v > topoheight) {
                // Case 1: prev topo is below or equal to requested topoheight => update it
                // Case 2: prev topo is None but pointer is Some => we update it
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != account.nonce_pointer {
                    account.nonce_pointer = filtered;
                    Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Account, key.as_bytes(), &account)?;
                }
            }
        }

        Ok(())
    }

    // delete versioned nonces below topoheight
    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        let start = topoheight.to_be_bytes();
        if keep_last {
            for res in Self::iter_owned_internal::<(), Account>(&self.db, self.snapshot.as_ref(), IteratorMode::Start, Column::Account)? {
                let (_, account) = res?;

                if let Some(topo) = account.nonce_pointer {
                    // We fetch the last version to take its previous topoheight
                    // And we loop on it to delete them all until the end of the chained data
                    let mut prev_version = Some(topo);
                    // If we are already below the threshold, we can directly erase without patching
                    let mut patched = topo < topoheight;
                    while let Some(prev_topo) = prev_version {
                        let key = Self::get_versioned_account_key(account.id, prev_topo);
    
                        // Delete this version from DB if its below the threshold
                        prev_version = self.load_from_disk(Column::VersionedNonces, &key)?;
                        if patched {
                            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedNonces, &key)?;
                        } else {
                            if prev_version.is_some_and(|v| v < topoheight) {
                                trace!("Patching versioned data at topoheight {}", topoheight);
                                patched = true;
                                let mut data: Versioned<RawBytes> = self.load_from_disk(Column::VersionedNonces, &key)?;
                                data.set_previous_topoheight(None);

                                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedNonces, &key, &data)?;
                            }
                        }
                    }
                }
            }
        } else {
            for res in Self::iter_owned_internal::<RawBytes, ()>(&self.db, self.snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedNonces)? {
                let (key, _) = res?;
                Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedNonces, &key)?;
            }
        }

        Ok(())
    }
}