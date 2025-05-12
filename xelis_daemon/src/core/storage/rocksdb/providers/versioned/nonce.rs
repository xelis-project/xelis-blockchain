use async_trait::async_trait;
use log::trace;
use xelis_common::{block::TopoHeight, serializer::{RawBytes, Serializer}};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{AccountId, Column},
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
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>, _>(&self.db, self.snapshot.as_ref(), Some(topoheight.to_be_bytes()), Column::VersionedNonces)? {
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
        todo!()
    }

    // delete versioned nonces below topoheight
    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        todo!()
    }
}