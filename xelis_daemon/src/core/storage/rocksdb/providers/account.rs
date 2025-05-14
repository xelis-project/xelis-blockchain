use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
    serializer::Skip
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            Account,
            AccountId,
            AssetId,
            Column,
            IteratorMode,
        },
        AccountProvider,
        NetworkProvider,
        RocksStorage
    }
};

#[async_trait]
impl AccountProvider for RocksStorage {
    // Get the number of accounts with nonces available on chain
    async fn count_accounts(&self) -> Result<u64, BlockchainError> {
        trace!("count accounts");
        self.get_last_account_id()
    }

    // first time we saw this account on chain
    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        trace!("get account {} registration topoheight", key.as_address(self.is_mainnet()));
        let account = self.get_account_type(key)?;
        account.registered_at
            .ok_or(BlockchainError::UnknownAccount)
    }

    // set the registration topoheight
    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set account {} registration topoheight to {}", key.as_address(self.is_mainnet()), topoheight);
        let mut account = self.get_or_create_account_type(key)?;
        account.registered_at = Some(topoheight);

        self.insert_into_disk(Column::Account, key.as_bytes(), &account)
    }

    // delete the registration of an account
    async fn delete_account_for(&mut self, key: &PublicKey) -> Result<(), BlockchainError> {
        trace!("delete account {} registration", key.as_address(self.is_mainnet()));
        let mut account = self.get_or_create_account_type(key)?;
        account.registered_at = None;
        account.nonce_pointer = None;
        account.multisig_pointer = None;

        self.insert_into_disk(Column::Account, key.as_bytes(), &account)
    }

    // Check if account is registered
    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        trace!("is account {} registered", key.as_address(self.is_mainnet()));
        self.has_account_type(key)
    }

    // Check if account is registered at topoheight
    // This will check that the registration topoheight is less or equal to the given topoheight
    async fn is_account_registered_for_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("is account {} registered for topoheight {}", key.as_address(self.is_mainnet()), topoheight);
        let account = self.get_optional_account_type(key)?;
        match account {
            Some(account) => Ok(account.registered_at.map_or(false, |t| t <= topoheight)),
            None => Ok(false)
        }
    }

    // Get registered accounts supporting pagination and filtering by topoheight
    // Returned keys must have a nonce or a balance updated in the range given
    async fn get_registered_keys<'a>(&'a self, minimum_topoheight: Option<TopoHeight>, maximum_topoheight: Option<TopoHeight>) -> Result<impl Iterator<Item = Result<PublicKey, BlockchainError>> + 'a, BlockchainError> {
        trace!("get registered keys with topoheight range {:?} - {:?}", minimum_topoheight, maximum_topoheight);
        // We actually only read the registered_at field
        Ok(self.iter::<PublicKey, Skip<8, Option<u64>>>(Column::Account, IteratorMode::Start)?
            .map(move |res| {
                let (key, value) = res?;
                let Some(registered_at) = value.0 else {
                    trace!("skipping account {} with no registered_at", key.as_address(self.is_mainnet()));
                    return Ok(None)
                };

                // Skip if not in range
                if minimum_topoheight.is_some_and(|v| registered_at < v) || maximum_topoheight.is_some_and(|v| registered_at > v) {
                    trace!("skipping account {} with registered_at {} not in range", key.as_address(self.is_mainnet()), registered_at);
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
        trace!("has key {} updated in range {:?} - {:?}", key.as_address(self.is_mainnet()), minimum_topoheight, maximum_topoheight);
        let Some(account) = self.get_optional_account_type(key)? else {
            trace!("account {} not found", key.as_address(self.is_mainnet()));
            return Ok(false)
        };

        let Some(registered_at) = account.registered_at else {
            trace!("account {} has no registered_at", key.as_address(self.is_mainnet()));
            return Ok(false)
        };

        if registered_at > maximum_topoheight {
            trace!("account {} registered_at {} not in range", key.as_address(self.is_mainnet()), registered_at);
            return Ok(false)
        }

        let Some(nonce_pointer) = account.nonce_pointer else {
            trace!("account {} has no nonce_pointer", key.as_address(self.is_mainnet()));
            return Ok(false)
        };

        // Check if the nonce is in the range
        if nonce_pointer >= minimum_topoheight && nonce_pointer <= maximum_topoheight {
            trace!("account {} nonce_pointer {} in range", key.as_address(self.is_mainnet()), nonce_pointer);
            return Ok(true)
        }

        // for the key, we only read the asset id, we skip the 8 bytes representing the account ID
        // as we already know it as we iter prefix on it
        let prefix = account.id.to_be_bytes();
        for res in self.iter::<Skip<8, AssetId>, TopoHeight>(Column::Balances, IteratorMode::WithPrefix(&prefix, Direction::Forward))? {
            let (k, topo) = res?;

            let asset_id = k.0;
            let mut next_topo = Some(topo);
            while let Some(topo) = next_topo {
                if topo < minimum_topoheight {
                    trace!("skipping asset {} at {} below minimum topoheight {}", asset_id, topo, minimum_topoheight);
                    break;
                }

                if topo <= maximum_topoheight {
                    trace!("account {} asset {} balance updated at {}", key.as_address(self.is_mainnet()), asset_id, topo);
                    return Ok(true)
                }

                let key = Self::get_versioned_account_balance_key(account.id, asset_id, topo);
                next_topo = self.load_from_disk(Column::VersionedBalances, &key)?;
            }
        }

        Ok(false)
    }
}

impl RocksStorage {
    const NEXT_ACCOUNT_ID: &[u8] = b"NAID";

    fn get_last_account_id(&self) -> Result<AccountId, BlockchainError> {
        trace!("get current account id");
        self.load_optional_from_disk::<_, AccountId>(Column::Common, Self::NEXT_ACCOUNT_ID)
            .map(|v| v.unwrap_or(0))
    }

    fn get_next_account_id(&mut self) -> Result<u64, BlockchainError> {
        trace!("get next account id");
        let id = self.get_last_account_id()?;
        trace!("next account id is {}", id);
        self.insert_into_disk(Column::Common, Self::NEXT_ACCOUNT_ID, &(id + 1))?;

        Ok(id)
    }

    pub(super) fn get_versioned_account_key(key: AccountId, topoheight: TopoHeight) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[0..8].copy_from_slice(&topoheight.to_be_bytes());
        bytes[8..16].copy_from_slice(&key.to_be_bytes());

        bytes
    }

    pub(super) fn has_account_type(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        trace!("has account {}", key.as_address(self.is_mainnet()));
        self.contains_data(Column::Account, key.as_bytes())
    }

    pub(super) fn get_account_id(&self, key: &PublicKey) -> Result<u64, BlockchainError> {
        self.get_optional_account_id(key)?
            .ok_or_else(|| BlockchainError::AccountNotFound(key.as_address(self.is_mainnet())))
    }

    pub(super) fn get_optional_account_id(&self, key: &PublicKey) -> Result<Option<u64>, BlockchainError> {
        trace!("get optional account id {}", key.as_address(self.is_mainnet()));
        // This will read just the id
        // TODO: cache
        self.load_optional_from_disk(Column::Account, key.as_bytes())
    }

    pub(super) fn get_account_key_from_id(&self, id: AccountId) -> Result<PublicKey, BlockchainError> {
        trace!("get account key from id {}", id);
        self.load_from_disk(Column::AccountById, &id.to_be_bytes())
    }

    pub(super) fn get_account_type(&self, key: &PublicKey) -> Result<Account, BlockchainError> {
        trace!("get account {}", key.as_address(self.is_mainnet()));
        self.load_from_disk(Column::Account, key.as_bytes())
    }

    pub(super) fn get_optional_account_type(&self, key: &PublicKey) -> Result<Option<Account>, BlockchainError> {
        trace!("get optional account {}", key.as_address(self.is_mainnet()));
        self.load_optional_from_disk(Column::Account, key.as_bytes())
    }

    // Get or create an account type
    // You must store the account type in case its created!
    pub(super) fn get_or_create_account_type(&mut self, key: &PublicKey) -> Result<Account, BlockchainError> {
        trace!("get or create account {}", key.as_address(self.is_mainnet()));
        match self.get_optional_account_type(key)? {
            Some(account) => Ok(account),
            None => {
                trace!("creating account {}", key.as_address(self.is_mainnet()));
                let account = Account {
                    id: self.get_next_account_id()?,
                    registered_at: None,
                    nonce_pointer: None,
                    multisig_pointer: None,
                };

                self.insert_into_disk(Column::AccountById, account.id.to_be_bytes(), key.as_bytes())?;

                Ok(account)
            }
        }
    }
}