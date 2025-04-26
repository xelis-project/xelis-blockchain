use async_trait::async_trait;
use log::trace;
use xelis_common::{
    account::VersionedNonce,
    block::TopoHeight,
    crypto::PublicKey,
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{sled::ACCOUNTS_COUNT, SledStorage},
};

use super::NetworkProvider;

#[async_trait]
pub trait NonceProvider {
    // Check if the account has a nonce
    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError>;

    // Get the number of accounts with nonces available on chain
    async fn count_accounts(&self) -> Result<u64, BlockchainError>;

    // Check if the account has a nonce at a specific topoheight
    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the last topoheigh that the account has a nonce
    async fn get_last_topoheight_for_nonce(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError>;

    // Get the last nonce of the account, this is based on the last topoheight available
    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(TopoHeight, VersionedNonce), BlockchainError>;

    // Get the nonce at a specific topoheight for an account
    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<VersionedNonce, BlockchainError>;

    // Get the nonce under or equal topoheight requested for an account
    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedNonce)>, BlockchainError>;

    // Set the last topoheight that the account has a nonce changed
    async fn set_last_topoheight_for_nonce(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Delete the last topoheight that the account has a nonce
    // This is only removing the pointer, not the version itself
    async fn delete_last_topoheight_for_nonce(&mut self, key: &PublicKey) -> Result<(), BlockchainError>;

    // set the new nonce at exact topoheight for account
    // This will do like `set_nonce_at_topoheight` but will also update the pointer
    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: TopoHeight, nonce: &VersionedNonce) -> Result<(), BlockchainError>;

    // set a new nonce at specific topoheight for account
    async fn set_nonce_at_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight, version: &VersionedNonce) -> Result<(), BlockchainError>;
}

impl SledStorage {
    // Update the accounts count and store it on disk
    pub fn store_accounts_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.cache.accounts_count = count;
        } else {
            self.cache.accounts_count = count;
        }
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, ACCOUNTS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }

    // Versioned key is a 40 bytes key with topoheight as first bytes and the key as last bytes
    pub fn get_versioned_nonce_key(&self, key: &PublicKey, topoheight: TopoHeight) -> [u8; 40] {
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
        let count = if let Some(snapshot) = self.snapshot.as_ref() {
            snapshot.cache.accounts_count
        } else {
            self.cache.accounts_count
        };
        Ok(count)
    }

    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: TopoHeight, version: &VersionedNonce) -> Result<(), BlockchainError> {
        trace!("set last nonce {} for {} at topoheight {}", version.get_nonce(), key.as_address(self.is_mainnet()), topoheight);
        self.set_nonce_at_topoheight(key, topoheight, version).await?;
        self.set_last_topoheight_for_nonce(key, topoheight).await?;
        Ok(())
    }

    async fn delete_last_topoheight_for_nonce(&mut self, key: &PublicKey) -> Result<(), BlockchainError> {
        trace!("delete last topoheight for nonce {}", key.as_address(self.is_mainnet()));
        let prev = Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.nonces, key.as_bytes())?;
        if prev {
            self.store_accounts_count(self.count_accounts().await? - 1)?;
        }
        Ok(())
    }

    async fn get_last_topoheight_for_nonce(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        trace!("get last topoheight for nonce {}", key.as_address(self.is_mainnet()));
        self.load_from_disk(&self.nonces, key.as_bytes(), DiskContext::LastTopoheightForNonce)
    }

    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        trace!("has nonce {}", key.as_address(self.is_mainnet()));
        let contains = self.contains_data(&self.nonces, key.as_bytes())?;
        Ok(contains)
    }

    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has nonce {} at topoheight {}", key.as_address(self.is_mainnet()), topoheight);
        let key = self.get_versioned_nonce_key(key, topoheight);
        self.contains_data(&self.versioned_nonces, &key)
    }

    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(TopoHeight, VersionedNonce), BlockchainError> {
        trace!("get last nonce {}", key.as_address(self.is_mainnet()));
        if !self.has_nonce(key).await? {
            return Err(BlockchainError::NoNonce(key.as_address(self.is_mainnet())))
        }

        let topoheight = self.load_from_disk(&self.nonces, key.as_bytes(), DiskContext::LastNonce)?;
        Ok((topoheight, self.get_nonce_at_exact_topoheight(key, topoheight).await?))
    }

    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<VersionedNonce, BlockchainError> {
        trace!("get nonce at topoheight {} for {}", topoheight, key.as_address(self.is_mainnet()));

        let key = self.get_versioned_nonce_key(key, topoheight);
        self.load_from_disk(&self.versioned_nonces, &key, DiskContext::NonceAtTopoHeight(topoheight))
    }

    // topoheight is inclusive bounds
    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedNonce)>, BlockchainError> {
        trace!("get nonce at maximum topoheight {} for {}", topoheight, key.as_address(self.is_mainnet()));
        // check first that this address has nonce, if no returns None
        if !self.has_nonce(key).await? {
            return Ok(None)
        }

        // Fast path check
        let topo = if self.has_nonce_at_exact_topoheight(key, topoheight).await? {
            topoheight
        } else {
            self.get_last_topoheight_for_nonce(key).await?
        };

        // otherwise, we have to go through the whole chain
        let mut topo = Some(topo);
        while let Some(previous) = topo {
            trace!("previous nonce version is at {}", previous);
            if previous <= topoheight {
                trace!("Highest version nonce found at {} (maximum topoheight = {})", previous, topoheight);
                let version = self.get_nonce_at_exact_topoheight(key, previous).await?;
                return Ok(Some((previous, version)))
            }

            topo = self.load_from_disk(&self.versioned_nonces, &Self::get_versioned_key(key.as_bytes(), previous), DiskContext::LastNonce)?;
        }

        Ok(None)
    }

    async fn set_nonce_at_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight, version: &VersionedNonce) -> Result<(), BlockchainError> {
        trace!("set nonce to {} for {} at topo {}", version.get_nonce(), key.as_address(self.is_mainnet()), topoheight);
        let disk_key = self.get_versioned_nonce_key(key, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_nonces, &disk_key, version.to_bytes())?;
        Ok(())
    }

    async fn set_last_topoheight_for_nonce(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set last topoheight for nonce {} to {}", key.as_address(self.is_mainnet()), topoheight);
        let prev = Self::insert_into_disk(self.snapshot.as_mut(), &self.nonces, key.as_bytes(), &topoheight.to_be_bytes())?;
        if prev.is_none() {
            self.store_accounts_count(self.count_accounts().await? + 1)?;
        }

        Ok(())
    }
}