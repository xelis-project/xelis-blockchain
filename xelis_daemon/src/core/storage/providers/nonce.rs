use std::sync::atomic::Ordering;

use async_trait::async_trait;
use indexmap::IndexSet;
use log::{trace, error};
use xelis_common::{
    account::VersionedNonce,
    crypto::PublicKey,
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::{sled::ACCOUNTS_COUNT, SledStorage},
};

use super::{AssetProvider, BalanceProvider};

#[async_trait]
pub trait NonceProvider: BalanceProvider {
    // Check if the account has a nonce
    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError>;

    // Get the number of accounts with nonces available on chain
    async fn count_accounts(&self) -> Result<u64, BlockchainError>;

    // Check if the account has a nonce at a specific topoheight
    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<bool, BlockchainError>;

    // Get registered accounts supporting pagination and filtering by topoheight
    // Returned keys must have a nonce or a balance updated in the range given
    async fn get_partial_keys(&self, maximum: usize, skip: usize, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<IndexSet<PublicKey>, BlockchainError>;

    // Get the last topoheigh that the account has a nonce
    async fn get_last_topoheight_for_nonce(&self, key: &PublicKey) -> Result<u64, BlockchainError>;

    // Get the last nonce of the account, this is based on the last topoheight available
    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(u64, VersionedNonce), BlockchainError>;

    // Get the nonce at a specific topoheight for an account
    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<VersionedNonce, BlockchainError>;

    // Get the nonce under or equal topoheight requested for an account
    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<Option<(u64, VersionedNonce)>, BlockchainError>;

    // Check if the account has a nonce updated in the range given
    // It will also check balances if no nonce found
    async fn has_key_updated_in_range(&self, key: &PublicKey, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<bool, BlockchainError>;

    // Set the last topoheight that the account has a nonce changed
    async fn set_last_topoheight_for_nonce(&mut self, key: &PublicKey, topoheight: u64) -> Result<(), BlockchainError>;

    // Delete the last topoheight that the account has a nonce
    // This is only removing the pointer, not the version itself
    async fn delete_last_topoheight_for_nonce(&mut self, key: &PublicKey) -> Result<(), BlockchainError>;

    // set the new nonce at exact topoheight for account
    // This will do like `set_nonce_at_topoheight` but will also update the pointer
    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: u64, nonce: &VersionedNonce) -> Result<(), BlockchainError>;

    // set a new nonce at specific topoheight for account
    async fn set_nonce_at_topoheight(&mut self, key: &PublicKey, topoheight: u64, version: &VersionedNonce) -> Result<(), BlockchainError>;
}

impl SledStorage {
    // Update the accounts count and store it on disk
    pub fn store_accounts_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        self.accounts_count.store(count, Ordering::SeqCst);
        self.extra.insert(ACCOUNTS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }

    // Versioned key is a 40 bytes key with topoheight as first bytes and the key as last bytes
    pub fn get_versioned_nonce_key(&self, key: &PublicKey, topoheight: u64) -> [u8; 40] {
        trace!("get versioned balance key at {} for {}", topoheight, key.as_address(self.is_mainnet()));
        let mut bytes = [0; 40];
        bytes[0..8].copy_from_slice(&topoheight.to_be_bytes());
        bytes[8..40].copy_from_slice(key.as_bytes());

        bytes
    }
}

#[async_trait]
impl NonceProvider for SledStorage {
    async fn count_accounts(&self) -> Result<u64, BlockchainError> {
        trace!("count accounts");
        Ok(self.accounts_count.load(Ordering::SeqCst))
    }

    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: u64, version: &VersionedNonce) -> Result<(), BlockchainError> {
        trace!("set last nonce {} for {} at topoheight {}", version.get_nonce(), key.as_address(self.is_mainnet()), topoheight);
        self.set_nonce_at_topoheight(key, topoheight, version).await?;
        self.set_last_topoheight_for_nonce(key, topoheight).await?;
        Ok(())
    }

    async fn delete_last_topoheight_for_nonce(&mut self, key: &PublicKey) -> Result<(), BlockchainError> {
        trace!("delete last topoheight for nonce {}", key.as_address(self.is_mainnet()));
        if self.nonces.remove(key.as_bytes())?.is_some() {
            self.store_accounts_count(self.count_accounts().await? - 1)?;
        }
        Ok(())
    }

    async fn get_last_topoheight_for_nonce(&self, key: &PublicKey) -> Result<u64, BlockchainError> {
        trace!("get last topoheight for nonce {}", key.as_address(self.is_mainnet()));
        self.load_from_disk(&self.nonces, key.as_bytes())
    }

    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        trace!("has nonce {}", key.as_address(self.is_mainnet()));
        let contains = self.nonces.contains_key(key.as_bytes())?;
        Ok(contains)
    }

    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<bool, BlockchainError> {
        trace!("has nonce {} at topoheight {}", key.as_address(self.is_mainnet()), topoheight);
        let key = self.get_versioned_nonce_key(key, topoheight);
        self.contains_data::<_, ()>(&self.versioned_nonces, &None, &key).await
    }

    // Get all keys that got a changes in their balances/nonces in the range given
    async fn get_partial_keys(&self, maximum: usize, skip: usize, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<IndexSet<PublicKey>, BlockchainError> {
        trace!("get partial keys, maximum: {}, skip: {}, minimum_topoheight: {}, maximum_topoheight: {}", maximum, skip, minimum_topoheight, maximum_topoheight);

        let mut keys: IndexSet<PublicKey> = IndexSet::new();
        let mut skip_count = 0;
        for el in self.nonces.iter().keys() {
            let key = el?;
            let pkey = PublicKey::from_bytes(&key)?;

            // check that we have a nonce before the maximum topoheight
            if self.has_key_updated_in_range(&pkey, minimum_topoheight, maximum_topoheight).await? {
                if skip_count < skip {
                    skip_count += 1;
                } else {
                    keys.insert(pkey);

                    if keys.len() == maximum {
                        break;
                    }
                }
            }
        }

        Ok(keys)
    }

    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(u64, VersionedNonce), BlockchainError> {
        trace!("get last nonce {}", key.as_address(self.is_mainnet()));
        if !self.has_nonce(key).await? {
            return Err(BlockchainError::NoNonce(key.as_address(self.is_mainnet())))
        }

        let topoheight = self.load_from_disk(&self.nonces, key.as_bytes())?;
        Ok((topoheight, self.get_nonce_at_exact_topoheight(key, topoheight).await?))
    }

    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<VersionedNonce, BlockchainError> {
        trace!("get nonce at topoheight {} for {}", topoheight, key.as_address(self.is_mainnet()));

        let key = self.get_versioned_nonce_key(key, topoheight);
        self.load_from_disk(&self.versioned_nonces, &key)
    }

    // topoheight is inclusive bounds
    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<Option<(u64, VersionedNonce)>, BlockchainError> {
        trace!("get nonce at maximum topoheight {} for {}", topoheight, key.as_address(self.is_mainnet()));
        // check first that this address has nonce, if no returns None
        if !self.has_nonce(key).await? {
            return Ok(None)
        }

        let (topo, mut version) = self.get_last_nonce(key).await?;
        trace!("Last version of nonce for {} is at topoheight {}", key.as_address(self.is_mainnet()), topo);
        // if it's the latest and its under the maximum topoheight
        if topo <= topoheight {
            trace!("Last version nonce (valid) found at {} (maximum topoheight = {})", topo, topoheight);
            return Ok(Some((topo, version)))
        }

        // otherwise, we have to go through the whole chain
        while let Some(previous) = version.get_previous_topoheight() {
            let previous_version = self.get_nonce_at_exact_topoheight(key, previous).await?;
            trace!("previous nonce version is at {}", previous);
            if previous <= topoheight {
                trace!("Highest version nonce found at {} (maximum topoheight = {})", previous, topoheight);
                return Ok(Some((previous, previous_version)))
            }

            if let Some(value) = previous_version.get_previous_topoheight() {
                if value > previous {
                    error!("FATAL ERROR: Previous topoheight ({}) should not be higher than current version ({})!", value, previous);
                    return Err(BlockchainError::Unknown)
                }
            }
            version = previous_version;
        }

        Ok(None)
    }

    async fn has_key_updated_in_range(&self, key: &PublicKey, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<bool, BlockchainError> {
        trace!("has key {} updated in range min topoheight {} and max topoheight {}", key.as_address(self.is_mainnet()), minimum_topoheight, maximum_topoheight);
        // check first that this address has nonce, if no returns None
        if !self.has_nonce(key).await? {
            return Ok(false)
        }

        // fast path check the latest nonce
        let (topo, mut version) = self.get_last_nonce(key).await?;
        trace!("Last version of nonce for {} is at topoheight {}", key.as_address(self.is_mainnet()), topo);

        // if it's the latest and its under the maximum topoheight and above minimum topoheight
        if topo >= minimum_topoheight && topo <= maximum_topoheight {
            trace!("Last version nonce (valid) found at {} (maximum topoheight = {})", topo, maximum_topoheight);
            return Ok(true)
        }

        // otherwise, we have to go through the whole chain
        while let Some(previous) = version.get_previous_topoheight() {
            // we are under the minimum topoheight, we can stop
            if previous < minimum_topoheight {
                break;
            }

            let previous_version = self.get_nonce_at_exact_topoheight(key, previous).await?;
            trace!("previous nonce version is at {}", previous);
            if previous <= maximum_topoheight {
                trace!("Highest version nonce found at {} (maximum topoheight = {})", previous, maximum_topoheight);
                return Ok(true)
            }

            // security in case of DB corruption
            if let Some(value) = previous_version.get_previous_topoheight() {
                if value > previous {
                    error!("FATAL ERROR: Previous topoheight ({}) should not be higher than current version ({})!", value, previous);
                    return Err(BlockchainError::Unknown)
                }
            }
            version = previous_version;
        }

        // if we are here, we didn't find any nonce in the range
        // it start to be more and more heavy...
        // lets check on balances now...

        // check that we have a VersionedBalance between range given
        for asset in self.get_assets_for(key).await? {
            let (topo, mut version) = self.get_last_balance(key, &asset).await?;
            if topo >= minimum_topoheight && topo <= maximum_topoheight {
                return Ok(true)
            }

            while let Some(previous) = version.get_previous_topoheight() {
                // we are under the minimum topoheight, we can stop
                if previous < minimum_topoheight {
                    break;
                }

                let previous_version = self.get_balance_at_exact_topoheight(key, &asset, previous).await?;
                if previous <= maximum_topoheight {
                    return Ok(true)
                }

                // security in case of DB corruption
                if let Some(value) = previous_version.get_previous_topoheight() {
                    if value > previous {
                        error!("FATAL ERROR: Previous topoheight for balance ({}) should not be higher than current version of balance ({})!", value, previous);
                        return Err(BlockchainError::Unknown)
                    }
                }
                version = previous_version;
            }
        }

        Ok(false)
    }

    async fn set_nonce_at_topoheight(&mut self, key: &PublicKey, topoheight: u64, version: &VersionedNonce) -> Result<(), BlockchainError> {
        trace!("set nonce to {} for {} at topo {}", version.get_nonce(), key.as_address(self.is_mainnet()), topoheight);
        let disk_key = self.get_versioned_nonce_key(key, topoheight);
        self.versioned_nonces.insert(&disk_key, version.to_bytes())?;
        Ok(())
    }

    async fn set_last_topoheight_for_nonce(&mut self, key: &PublicKey, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("set last topoheight for nonce {} to {}", key.as_address(self.is_mainnet()), topoheight);
        if self.nonces.insert(&key.as_bytes(), &topoheight.to_be_bytes())?.is_none() {
            self.store_accounts_count(self.count_accounts().await? + 1)?;
        }

        Ok(())
    }
}