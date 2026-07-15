use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{AccountId, Column},
        MultiSigProvider,
        NetworkProvider,
        RocksStorage,
        VersionedMultiSig
    }
};

#[async_trait]
impl MultiSigProvider for RocksStorage {
    // Retrieve the last topoheight for a given account
    async fn get_last_topoheight_for_multisig(&self, key: &PublicKey) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get last topoheight for multisig for {}", key.as_address(self.is_mainnet()));
        self.get_optional_account_type(key)
            .map(|account| account.and_then(|account| account.multisig_pointer))
    }

    // Retrieve a multisig setup for a given account
    async fn get_multisig_at_topoheight_for<'a>(&'a self, key: &PublicKey, topoheight: TopoHeight) -> Result<VersionedMultiSig<'a>, BlockchainError> {
        trace!("get multisig at topoheight for {}", key.as_address(self.is_mainnet()));
        let account_id = self.get_account_id(key)?;
        let key = Self::get_versioned_multisig_key(account_id, topoheight);

        self.load_from_disk(Column::VersionedMultisig, &key)
    }

    // Retrieve the multisig setup at the maximum topoheight for a given account
    async fn get_multisig_at_maximum_topoheight_for<'a>(&'a self, account: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedMultiSig<'a>)>, BlockchainError> {
        trace!("get multisig at maximum topoheight for {}", account.as_address(self.is_mainnet()));        
        self.run_blocking(|| {
            let Some(account) = self.get_optional_account_type(account)? else {
                return Ok(None);
            };

            let mut previous_topoheight = if self.contains_data(Column::VersionedMultisig, &Self::get_versioned_multisig_key(account.id, maximum_topoheight))? {
                Some(maximum_topoheight)
            } else {
                account.multisig_pointer
            };

            while let Some(topoheight) = previous_topoheight {
                let versioned_key = Self::get_versioned_multisig_key(account.id, topoheight);
                if topoheight <= maximum_topoheight {
                    let version = self.load_from_disk(Column::VersionedMultisig, &versioned_key)?;
                    return Ok(Some((topoheight, version)));
                }

                previous_topoheight = self.load_from_disk(Column::VersionedMultisig, &versioned_key)?;
            }

            Ok(None)
        })
    }

    // Verify if an account has a multisig setup
    // If the latest version is None, the account has no multisig setup
    async fn has_multisig(&self, account: &PublicKey) -> Result<bool, BlockchainError> {
        trace!("has multisig for {}", account.as_address(self.is_mainnet()));
        let Some(account) = self.get_optional_account_type(account)? else {
            return Ok(false)
        };

        let Some(topoheight) = account.multisig_pointer else {
            return Ok(false)
        };

        let key = Self::get_versioned_multisig_key(account.id, topoheight);
        let version: VersionedMultiSig = self.load_from_disk(Column::VersionedMultisig, &key)?;
        Ok(version.get().is_some())
    }

    // Verify if a version exists at a given topoheight
    async fn has_multisig_at_exact_topoheight(&self, account: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has multisig at exact topoheight for account {}", account.as_address(self.is_mainnet()));
        let Some(account_id) = self.get_optional_account_id(account)? else {
            return Ok(false)
        };
        let versioned_key = Self::get_versioned_multisig_key(account_id, topoheight);

        self.contains_data(Column::VersionedMultisig, &versioned_key)
    }

    // Retrieve the last multisig setup for a given account
    async fn get_last_multisig<'a>(&'a self, account: &PublicKey) -> Result<(TopoHeight, VersionedMultiSig<'a>), BlockchainError> {
        trace!("get last multisig for {}", account.as_address(self.is_mainnet()));
        let account = self.get_account_type(account)?;
        let topoheight = account.multisig_pointer
            .ok_or(BlockchainError::MultisigNotFound)?;

        let key = Self::get_versioned_multisig_key(account.id, topoheight);
        let version = self.load_from_disk(Column::VersionedMultisig, &key)?;
        Ok((topoheight, version))
    }

    // Store the last multisig setup for a given account
    async fn set_last_multisig_to<'a>(&mut self, key: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError> {
        trace!("set last multisig to {} for {}", topoheight, key.as_address(self.is_mainnet()));
        let mut account = self.get_or_create_account_type(key)?;
        account.multisig_pointer = Some(topoheight);

        let versioned_key = Self::get_versioned_multisig_key(account.id, topoheight);

        self.insert_into_disk(Column::VersionedMultisig, &versioned_key, &multisig)?;
        self.insert_into_disk(Column::Account, key.as_bytes(), &account)
    }
}

impl RocksStorage {
    fn get_versioned_multisig_key(account: AccountId, topoheight: TopoHeight) -> [u8; 16] {
        let mut buffer = [0; 16];
        buffer[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buffer[8..16].copy_from_slice(&account.to_be_bytes());

        buffer
    }
}