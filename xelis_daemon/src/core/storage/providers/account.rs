use async_trait::async_trait;
use indexmap::IndexSet;
use log::trace;
use xelis_common::{
    crypto::PublicKey,
    serializer::Serializer,
    block::TopoHeight,
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage
};

#[async_trait]
pub trait AccountProvider {
    // first time we saw this account on chain
    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError>;

    // set the registration topoheight
    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Check if account is registered
    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError>;

    // Check if account is registered at topoheight
    // This will check that the registration topoheight is less or equal to the given topoheight
    async fn is_account_registered_at_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Delete all registrations at a certain topoheight
    async fn delete_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Get registered accounts supporting pagination and filtering by topoheight
    // Returned keys must have a nonce or a balance updated in the range given
    async fn get_registered_keys(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexSet<PublicKey>, BlockchainError>;
}

fn prefixed_db_key(topoheight: TopoHeight, key: &PublicKey) -> [u8; 40] {
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
    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        self.load_from_disk(&self.registrations, key.as_bytes(), DiskContext::AccountRegistrationTopoHeight)
    }

    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        if let Some(old) = Self::insert_into_disk(self.snapshot.as_mut(), &self.registrations, key.as_bytes(), &topoheight.to_be_bytes())? {
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &prefixed_db_key_no_u64(&old, key))?;
        }

        Self::insert_into_disk(self.snapshot.as_mut(), &self.registrations_prefixed, &prefixed_db_key(topoheight, key), &[])?;

        Ok(())
    }

    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        let value = self.load_optional_from_disk::<TopoHeight>(&self.registrations, key.as_bytes())?;
        if let Some(topo) = value {
            let k = prefixed_db_key(topo, key);
            return self.contains_data(&self.registrations_prefixed, &k)
        }

        Ok(false)
    }

    async fn is_account_registered_at_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        if !self.is_account_registered(key).await? {
            return Ok(false);
        }

        let registration_topoheight = self.get_account_registration_topoheight(key).await?;
        Ok(registration_topoheight <= topoheight)
    }

    async fn delete_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        for el in self.registrations_prefixed.scan_prefix(topoheight.to_bytes()).keys() {
            let k = el?;
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &k)?;

            let key = &k[8..40];
            Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations, key)?;
        }

        Ok(())
    }

    // Get all keys that got registered in the range given
    async fn get_registered_keys(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexSet<PublicKey>, BlockchainError> {
        trace!("get partial keys, maximum: {}, skip: {}, minimum_topoheight: {}, maximum_topoheight: {}", maximum, skip, minimum_topoheight, maximum_topoheight);

        let mut keys: IndexSet<PublicKey> = IndexSet::new();
        let mut skip_count = 0;
        for el in self.registrations_prefixed.iter().keys() {
            let key = el?;
            let topo = TopoHeight::from_bytes(&key[0..8])?;

            // Skip if not in range
            if topo < minimum_topoheight || topo > maximum_topoheight {
                continue;
            }

            // Skip if asked
            if skip_count < skip {
                skip_count += 1;
                continue;
            }

            keys.insert(PublicKey::from_bytes(&key[8..40])?);
            if keys.len() >= maximum {
                break;
            }
        }

        Ok(keys)
    }
}