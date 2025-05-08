use async_trait::async_trait;
use xelis_common::{
    account::VersionedNonce,
    block::TopoHeight,
    crypto::PublicKey
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        NetworkProvider,
        NonceProvider,
        RocksStorage
    }
};

#[async_trait]
impl NonceProvider for RocksStorage {
    // Check if the account has a nonce
    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        self.get_optional_account_type(key)
            .map(|account| account.map_or(false, |account| {
                account.nonce_pointer.is_some()
            }))
    }

    // Check if the account has a nonce at a specific topoheight
    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let account_id = self.get_account_id(key)?;
        self.contains_data(Column::VersionedNonces, &Self::get_versioned_account_key(account_id, topoheight))
    }

    // Get the last topoheigh that the account has a nonce
    async fn get_last_topoheight_for_nonce(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        let account = self.get_account_type(key)?;
        account.nonce_pointer.ok_or(BlockchainError::UnknownAccount)
    }

    // Get the last nonce of the account, this is based on the last topoheight available
    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(TopoHeight, VersionedNonce), BlockchainError> {
        let account = self.get_account_type(key)?;
        let topoheight = account.nonce_pointer
            .ok_or_else(|| BlockchainError::NoNonce(key.as_address(self.is_mainnet())))?;

        let versioned_nonce = self.get_nonce_at_exact_topoheight(key, topoheight).await?;
        Ok((topoheight, versioned_nonce))
    }

    // Get the nonce at a specific topoheight for an account
    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<VersionedNonce, BlockchainError> {
        let account_id = self.get_account_id(key)?;
        self.load_from_disk(Column::VersionedNonces, &Self::get_versioned_account_key(account_id, topoheight))
    }

    // Get the nonce under or equal topoheight requested for an account
    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedNonce)>, BlockchainError> {
        let account = self.get_account_type(key)?;

        // Check if the account has a nonce at the requested topoheight
        // otherwise, we will use the pointer to the last topoheight
        let mut versioned_key = Self::get_versioned_account_key(account.id, topoheight);

        let mut next_topo = if self.contains_data(Column::VersionedNonces, &versioned_key)? {
            Some(topoheight)
        } else {
            account.nonce_pointer
        };

        // Iterate over our linked list of versions
        while let Some(topo) = next_topo {
            // Check if the account has a nonce at the requested topoheight
            versioned_key = Self::get_versioned_account_key(account.id, topo);
            if topo <= topoheight {
                let version = self.load_from_disk(Column::VersionedNonces, &versioned_key)?;
                return Ok(Some((topo, version)));
            }

            next_topo = self.load_from_disk(Column::VersionedNonces, &versioned_key)?;
        }

        Ok(None)
    }

    // set the new nonce at exact topoheight for account
    // This will do like `set_nonce_at_topoheight` but will also update the pointer
    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: TopoHeight, nonce: &VersionedNonce) -> Result<(), BlockchainError> {
        let mut account = self.get_or_create_account_type(key)?;
        account.nonce_pointer = Some(topoheight);

        self.insert_into_disk(Column::VersionedNonces, &Self::get_versioned_account_key(account.id, topoheight), nonce)?;
        self.insert_into_disk(Column::Account, key.as_bytes(), &account)
    }
}