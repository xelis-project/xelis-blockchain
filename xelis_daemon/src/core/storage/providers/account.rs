use async_trait::async_trait;
use xelis_common::{crypto::PublicKey, serializer::Serializer};
use crate::core::{error::BlockchainError, storage::SledStorage};

#[async_trait]
pub trait AccountProvider {
    // first time we saw this account on chain
    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<u64, BlockchainError>;

    // set the registration topoheight
    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: u64) -> Result<(), BlockchainError>;

    // Check if account is registered
    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError>;

    // Check if account is registered below topoheight
    async fn is_account_registered_below_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<bool, BlockchainError>;

    // Delete all registrations at a certain topoheight
    async fn delete_registrations_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;
}

fn prefixed_db_key(topoheight: u64, key: &PublicKey) -> [u8; 40] {
    prefixed_db_key_no_u64(&topoheight.to_bytes(), key)
}

fn prefixed_db_key_no_u64(topoheight: &[u8], key: &PublicKey) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[0..8].copy_from_slice(&topoheight);
    buf[8..40].copy_from_slice(key.as_bytes());
    buf
}


#[async_trait]
impl AccountProvider for SledStorage {
    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<u64, BlockchainError> {
        self.load_from_disk(&self.registrations, key.as_bytes())
    }

    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: u64) -> Result<(), BlockchainError> {
        if let Some(old) = self.registrations.insert(key.as_bytes(), topoheight.to_bytes())? {
            self.registrations_prefixed.remove(&prefixed_db_key_no_u64(&old, key))?;
        }

        self.registrations_prefixed.insert(prefixed_db_key(topoheight, key), &[])?;

        Ok(())
    }

    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        let value = self.load_optional_from_disk::<u64>(&self.registrations, key.as_bytes())?;
        if let Some(topo) = value {
            return Ok(self.registrations_prefixed.contains_key(prefixed_db_key(topo, key))?)
        }

        Ok(false)
    }

    async fn is_account_registered_below_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<bool, BlockchainError> {
        if !self.is_account_registered(key).await? {
            return Ok(false);
        }

        let registration_topoheight = self.get_account_registration_topoheight(key).await?;
        Ok(registration_topoheight < topoheight)
    }

    async fn delete_registrations_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        for el in self.registrations_prefixed.scan_prefix(topoheight.to_bytes()).keys() {
            let k = el?;
            self.registrations_prefixed.remove(&k)?;
            let key = &k[8..40];
            self.registrations.remove(key)?;
        }

        Ok(())
    }
}