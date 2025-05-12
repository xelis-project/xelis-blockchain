use async_trait::async_trait;
use xelis_common::{block::TopoHeight, serializer::{Serializer, RawBytes}};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{AccountId, Column},
        RocksStorage,
        VersionedMultiSigProvider
    }
};

#[async_trait]
impl VersionedMultiSigProvider for RocksStorage {
    // delete versioned multisigs at topoheight
    async fn delete_versioned_multisigs_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        for res in Self::iter_owned_internal::<RawBytes, Option<TopoHeight>, _>(&self.db, self.snapshot.as_ref(), Some(topoheight.to_be_bytes()), Column::VersionedMultisig)? {
            let (key, prev_topo) = res?;
            Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), Column::VersionedMultisig, &key)?;
            
            let key_without_prefix = &key[8..];
            let account_id = AccountId::from_bytes(&key_without_prefix[0..8])?;
            let account_key = self.get_account_key_from_id(account_id)?;
            let mut account = self.get_account_type(&account_key)?;
            if account.multisig_pointer.is_some_and(|pointer| pointer >= topoheight) {
                if let Some(prev_topo) = prev_topo {
                    account.multisig_pointer = Some(prev_topo);
                } else {
                    account.multisig_pointer = None;
                }

                Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), Column::Account, account_key.as_bytes(), &account)?;
            }
        }

        Ok(())
    }

    // delete versioned multisigs above topoheight
    async fn delete_versioned_multisigs_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // delete versioned multisigs below topoheight
    async fn delete_versioned_multisigs_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        todo!()
    }
}