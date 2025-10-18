use async_trait::async_trait;
use xelis_common::{block::TopoHeight, serializer::{Serializer, RawBytes}};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            AccountId,
            Column,
            IteratorMode
        },
        snapshot::Direction,
        RocksStorage,
        VersionedRegistrationsProvider
    }
};

#[async_trait]
impl VersionedRegistrationsProvider for RocksStorage {
    // delete versioned registrations at topoheight
    async fn delete_versioned_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let prefix = topoheight.to_be_bytes();
        let snapshot = self.snapshot.clone();
        for res in Self::iter_internal::<RawBytes, ()>(&self.db, snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::PrefixedRegistrations)? {
            let (key, _) = res?;
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::PrefixedRegistrations, &key)?;

            let key_without_prefix = &key[8..];
            let account_id = AccountId::from_bytes(&key_without_prefix[0..8])?;
            let account_key = self.get_account_key_from_id(account_id)?;
            let mut account = self.get_account_type(&account_key)?;

            if account.registered_at.is_some_and(|pointer| pointer >= topoheight) {
                account.registered_at = None;
                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Account, account_key.as_bytes(), &account)?;
            }
        }

        Ok(())
    }

    // delete versioned registrations above topoheight
    async fn delete_versioned_registrations_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let prefix = (topoheight + 1).to_be_bytes();
        let snapshot = self.snapshot.clone();
        for res in Self::iter_internal::<RawBytes, ()>(&self.db, snapshot.as_ref(), IteratorMode::From(&prefix, Direction::Forward), Column::PrefixedRegistrations)? {
            let (key, _) = res?;
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::PrefixedRegistrations, &key)?;

            let key_without_prefix = &key[8..];
            let account_id = AccountId::from_bytes(&key_without_prefix[0..8])?;
            let account_key = self.get_account_key_from_id(account_id)?;
            let mut account = self.get_account_type(&account_key)?;

            if account.registered_at.is_some_and(|pointer| pointer >= topoheight) {
                account.registered_at = None;
                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Account, account_key.as_bytes(), &account)?;
            }
        }

        Ok(())
    }
}