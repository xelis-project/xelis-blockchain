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
    storage::{
        sled::ACCOUNTS_COUNT,
        NetworkProvider,
        NonceProvider,
        SledStorage
    },
};

impl SledStorage {
    // Update the accounts count and store it on disk
    pub fn store_accounts_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        self.cache_mut().accounts_count = count;
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
    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: TopoHeight, version: &VersionedNonce) -> Result<(), BlockchainError> {
        trace!("set last nonce {} for {} at topoheight {}", version.get_nonce(), key.as_address(self.is_mainnet()), topoheight);

        let disk_key = self.get_versioned_nonce_key(key, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_nonces, &disk_key, version.to_bytes())?;

        // Also update the pointer
        Self::insert_into_disk(self.snapshot.as_mut(), &self.nonces, key.as_bytes(), &topoheight.to_be_bytes())?;

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
}