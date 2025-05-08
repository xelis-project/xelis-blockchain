use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight, crypto::PublicKey, serializer::Skip
};
use crate::core::{
    error::BlockchainError,
    storage::{rocksdb::{Account, AccountId, Column}, AccountProvider, RocksStorage}
};

#[async_trait]
impl AccountProvider for RocksStorage {
    // Get the number of accounts with nonces available on chain
    async fn count_accounts(&self) -> Result<u64, BlockchainError> {
        todo!()
    }

    // first time we saw this account on chain
    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        let account = self.get_account_type(key)?;
        account.registered_at
            .ok_or(BlockchainError::UnknownAccount)
    }

    // set the registration topoheight
    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let mut account = self.get_or_create_account_type(key)?;
        account.registered_at = Some(topoheight);

        self.insert_into_disk(Column::Account, key.as_bytes(), &account)
    }

    // delete the registration of an account
    async fn delete_account_for(&mut self, key: &PublicKey) -> Result<(), BlockchainError> {
        let mut account = self.get_or_create_account_type(key)?;
        account.registered_at = None;
        account.nonce_pointer = None;
        account.multisig_pointer = None;

        self.insert_into_disk(Column::Account, key.as_bytes(), &account)
    }

    // Check if account is registered
    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        self.has_account_type(key)
    }

    // Check if account is registered at topoheight
    // This will check that the registration topoheight is less or equal to the given topoheight
    async fn is_account_registered_for_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let account = self.get_optional_account_type(key)?;
        match account {
            Some(account) => Ok(account.registered_at.map_or(false, |t| t <= topoheight)),
            None => Ok(false)
        }
    }

    // Get registered accounts supporting pagination and filtering by topoheight
    // Returned keys must have a nonce or a balance updated in the range given
    async fn get_registered_keys<'a>(&'a self, minimum_topoheight: Option<TopoHeight>, maximum_topoheight: Option<TopoHeight>) -> Result<impl Iterator<Item = Result<PublicKey, BlockchainError>> + 'a, BlockchainError> {
        // We actually only read the registered_at field
        Ok(self.iter::<PublicKey, Skip<8, Option<u64>>>(Column::Account)?
            .map(move |res| {
                let (key, value) = res?;
                let Some(registered_at) = value.0 else {
                    return Ok(None)
                };

                // Skip if not in range
                if minimum_topoheight.is_some_and(|v| registered_at < v) || maximum_topoheight.is_some_and(|v| registered_at > v) {
                    return Ok(None);
                }

                Ok(Some(key))
            })
            .filter_map(Result::transpose)
        )
    }

    // Check if the account has a nonce updated in the range given
    // It will also check balances if no nonce found
    async fn has_key_updated_in_range(&self, key: &PublicKey, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let Some(account) = self.get_optional_account_type(key)? else {
            return Ok(false)
        };

        let Some(registered_at) = account.registered_at else {
            return Ok(false)
        };

        if registered_at < minimum_topoheight || registered_at > maximum_topoheight {
            return Ok(false)
        }

        let Some(nonce_pointer) = account.nonce_pointer else {
            return Ok(false)
        };

        // Check if the nonce is in the range
        if nonce_pointer >= minimum_topoheight && nonce_pointer <= maximum_topoheight {
            return Ok(true)
        }

        // TODO: get balances iter for account id

        todo!()
    }
}

impl RocksStorage {
    fn get_next_account_id(&mut self) -> Result<u64, BlockchainError> {
        let id = self.load_optional_from_disk(Column::Common, b"next_account_id")?
            .unwrap_or(0);

        self.insert_into_disk(Column::Account, b"next_account_id", &(id + 1))?;

        Ok(id)
    }

    pub(super) fn get_versioned_account_key(key: AccountId, topoheight: TopoHeight) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[0..8].copy_from_slice(&topoheight.to_be_bytes());
        bytes[8..16].copy_from_slice(&key.to_be_bytes());

        bytes
    }

    pub(super) fn has_account_type(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        self.contains_data(Column::Account, key.as_bytes())
    }

    pub(super) fn get_account_id(&self, key: &PublicKey) -> Result<u64, BlockchainError> {
        // This will read just the id
        // TODO: cache
        self.load_from_disk(Column::Account, key.as_bytes())
    }

    pub(super) fn get_account_type(&self, key: &PublicKey) -> Result<Account, BlockchainError> {
        self.load_from_disk(Column::Account, key.as_bytes())
    }

    pub(super) fn get_optional_account_type(&self, key: &PublicKey) -> Result<Option<Account>, BlockchainError> {
        self.load_optional_from_disk(Column::Account, key.as_bytes())
    }

    pub(super) fn get_or_create_account_type(&mut self, key: &PublicKey) -> Result<Account, BlockchainError> {
        match self.get_optional_account_type(key)? {
            Some(account) => Ok(account),
            None => {
                let account = Account {
                    id: self.get_next_account_id()?,
                    registered_at: None,
                    nonce_pointer: None,
                    multisig_pointer: None,
                };

                self.insert_into_disk(Column::Account, key.as_bytes(), &account)?;
                self.insert_into_disk(Column::AccountById, account.id.to_be_bytes(), key.as_bytes())?;

                Ok(account)
            }
        }
    }
}