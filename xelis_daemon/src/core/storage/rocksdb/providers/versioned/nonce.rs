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
        self.run_blocking_mut(|s| {
            let prefix = topoheight.to_be_bytes();
            let snapshot = s.snapshot.clone();
            for res in Self::iter_raw_internal(&s.db, snapshot.as_ref(), IteratorMode::WithPrefix(&prefix, Direction::Forward), Column::VersionedNonces)? {
                let (key, value) = res?;

                Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedNonces, &key)?;

                let key_without_prefix = &key[8..];
                let account_id = AccountId::from_bytes(&key_without_prefix[0..8])?;
                let account_key = s.get_account_key_from_id(account_id)?;
                let mut account = s.get_account_type(&account_key)?;

                if account.nonce_pointer.is_some_and(|pointer| pointer >= topoheight) {
                    let prev_topo = Option::from_bytes(&value)?;
                    account.nonce_pointer = prev_topo;

                    trace!("updating account {} with nonce set to {:?}", account_key.as_address(s.is_mainnet()), account.nonce_pointer);
                    Self::insert_into_disk_internal(&s.db, s.snapshot.as_mut(), Column::Account, account_key.as_bytes(), &account)?;
                }
            }

            Ok(())
        })
    }

    // delete versioned nonces above topoheight
    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces above topoheight {}", topoheight);
        self.run_blocking_mut(|s| {
            let start = (topoheight + 1).to_be_bytes();
            let snapshot = s.snapshot.clone();
            for res in Self::iter_raw_internal(&s.db, snapshot.as_ref(), IteratorMode::From(&start, Direction::Forward), Column::VersionedNonces)? {
                let (key, value) = res?;
                Self::remove_from_disk_internal(&s.db, s.snapshot.as_mut(), Column::VersionedNonces, &key)?;

                let account_id = AccountId::from_bytes(&key[8..16])?;
                let key = s.get_account_key_from_id(account_id)?;
                let mut account = s.get_account_type(&key)?;

                if account.nonce_pointer.is_none_or(|v| v > topoheight) {
                    let prev_topo = Option::from_bytes(&value)?;
                    let filtered = prev_topo.filter(|v| *v <= topoheight);
                    if filtered != account.nonce_pointer {
                        account.nonce_pointer = filtered;
                        Self::insert_into_disk_internal(&s.db, s.snapshot.as_mut(), Column::Account, key.as_bytes(), &account)?;
                    }
                }
            }

            Ok(())
        })
    }

    // delete versioned nonces below topoheight
    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces below topoheight {}", topoheight);
        self.delete_versioned_below_topoheight::<AccountId, Account>(Column::Account, Column::VersionedNonces, topoheight, keep_last, |_, v| Ok((v.id, v.nonce_pointer))).await
    }
}