use async_trait::async_trait;
use log::trace;
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
        trace!("has nonce for account {}", key.as_address(self.is_mainnet()));
        self.get_optional_account_type(key)
            .map(|account| account.map_or(false, |account| {
                account.nonce_pointer.is_some()
            }))
    }

    // Check if the account has a nonce at a specific topoheight
    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has nonce at exact topoheight for account {}", key.as_address(self.is_mainnet()));
        let account_id = self.get_account_id(key)?;
        self.contains_data(Column::VersionedNonces, &Self::get_versioned_account_key(account_id, topoheight))
    }

    // Get the last topoheigh that the account has a nonce
    async fn get_last_topoheight_for_nonce(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        trace!("get last topoheight for nonce for account {}", key.as_address(self.is_mainnet()));
        let account = self.get_account_type(key)?;
        account.nonce_pointer.ok_or(BlockchainError::UnknownAccount)
    }

    // Get the last nonce of the account, this is based on the last topoheight available
    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(TopoHeight, VersionedNonce), BlockchainError> {
        trace!("get last nonce for account {}", key.as_address(self.is_mainnet()));
        let account = self.get_account_type(key)?;
        let topoheight = account.nonce_pointer
            .ok_or_else(|| BlockchainError::NoNonce(key.as_address(self.is_mainnet())))?;

        let versioned_nonce = self.get_nonce_at_exact_topoheight(key, topoheight).await?;
        Ok((topoheight, versioned_nonce))
    }

    // Get the nonce at a specific topoheight for an account
    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<VersionedNonce, BlockchainError> {
        trace!("get nonce at exact topoheight for account {}", key.as_address(self.is_mainnet()));
        let account_id = self.get_account_id(key)?;
        self.load_from_disk(Column::VersionedNonces, &Self::get_versioned_account_key(account_id, topoheight))
    }

    // Get the nonce under or equal topoheight requested for an account
    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedNonce)>, BlockchainError> {
        trace!("get nonce at maximum topoheight for account {}", key.as_address(self.is_mainnet()));
        let account = self.get_account_type(key)?;

        // Check if the account has a nonce at the requested topoheight
        // otherwise, we will use the pointer to the last topoheight
        let Some(nonce_topoheight) = account.nonce_pointer else {
            trace!("no nonce pointer found for account");
            return Ok(None);
        };

        let mut next_topo = if nonce_topoheight > maximum_topoheight
            && self.contains_data(Column::VersionedNonces, &Self::get_versioned_account_key(account.id, maximum_topoheight))? {
            trace!("using maximum topoheight as start topo");
            Some(maximum_topoheight)
        } else {
            trace!("using nonce pointer {:?} as start topo", account.nonce_pointer);
            account.nonce_pointer
        };

        // Iterate over our linked list of versions
        while let Some(topo) = next_topo {
            // Check if the account has a nonce at the requested topoheight
            let versioned_key = Self::get_versioned_account_key(account.id, topo);
            if topo <= maximum_topoheight {
                trace!("found nonce at topoheight {} with maximum topoheight {}", topo, maximum_topoheight);
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
        trace!("set last nonce to {} for account {} at topoheight {}", nonce.get_nonce(), key.as_address(self.is_mainnet()), topoheight);
        let mut account = self.get_or_create_account_type(key)?;
        account.nonce_pointer = Some(topoheight);

        self.insert_into_disk(Column::VersionedNonces, &Self::get_versioned_account_key(account.id, topoheight), nonce)?;
        self.insert_into_disk(Column::Account, key.as_bytes(), &account)
    }
}