use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    serializer::Serializer,
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
        snapshot::Direction,
        RocksStorage,
        VersionedMultiSigProvider
    }
};

#[async_trait]
impl VersionedMultiSigProvider for RocksStorage {
    // delete versioned multisigs at topoheight
    async fn delete_versioned_multisigs_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned multisigs at topoheight {}", topoheight);
        let prefix = topoheight.to_be_bytes();

        let snapshot = self.snapshot.clone();
        for res in Self::iter_raw_internal(&self.db, snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedMultisig)? {
            let (key, value) = res?;
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedMultisig, &key)?;
            
            let key_without_prefix = &key[8..];
            let account_id = AccountId::from_bytes(&key_without_prefix[0..8])?;
            let account_key = self.get_account_key_from_id(account_id)?;
            let mut account = self.get_account_type(&account_key)?;
            if account.multisig_pointer.is_some_and(|pointer| pointer >= topoheight) {
                let prev_topo = Option::from_bytes(&value)?;
                account.multisig_pointer = prev_topo;

                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Account, account_key.as_bytes(), &account)?;
            }
        }

        Ok(())
    }

    // delete versioned multisigs above topoheight
    async fn delete_versioned_multisigs_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned multisigs above topoheight {}", topoheight);
        let start = (topoheight + 1).to_be_bytes();
        let snapshot = self.snapshot.clone();
        for res in Self::iter_raw_internal(&self.db, snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedMultisig)? {
            let (key, value) = res?;
            // Delete the version we've read
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedMultisig, &key)?;

            let account_id = AccountId::from_bytes(&key[8..16])?;
            let key = self.get_account_key_from_id(account_id)?;
            let mut account = self.get_account_type(&key)?;

            // This algorithm should be finding the latest valid data pointer
            // while limiting updates, it will write the highest
            // data pointer if any, or set to None

            // Case 1: data pointer is above topoheight => we update it
            // Case 2: data pointer is None => we update it
            if account.multisig_pointer.is_none_or(|v| v > topoheight) {
                // Case 1: prev topo is below or equal to requested topoheight => update it
                // Case 2: prev topo is None but pointer is Some => we update it
                let prev_topo = Option::from_bytes(&value)?;
                let filtered = prev_topo.filter(|v| *v <= topoheight);
                if filtered != account.multisig_pointer {
                    account.multisig_pointer = filtered;
                    Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Account, key.as_bytes(), &account)?;
                }
            }
        }

        Ok(())
    }

    // delete versioned multisigs below topoheight
    async fn delete_versioned_multisigs_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned multisigs below topoheight {}", topoheight);
        self.delete_versioned_below_topoheight::<Account, AccountId>(Column::Account, Column::VersionedMultisig, topoheight, keep_last, |_, v| Ok((v.id, v.multisig_pointer)))
    }
}