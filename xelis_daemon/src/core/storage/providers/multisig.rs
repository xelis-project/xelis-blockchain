use async_trait::async_trait;
use xelis_common::{
    crypto::PublicKey,
    serializer::Serializer,
    transaction::MultiSigPayload
};

use crate::core::{error::BlockchainError, storage::SledStorage};

#[async_trait]
pub trait MultiSigProvider {
    // Retrieve the last topoheight for a given account
    async fn get_multisig_last_topoheight_for(&self, account: &PublicKey) -> Result<Option<u64>, BlockchainError>;

    // Retrieve a multisig setup for a given account
    async fn get_multisig_at_topoheight_for(&self, account: &PublicKey, topoheight: u64) -> Result<Option<MultiSigPayload>, BlockchainError>;

    // Store a multisig setup for a given account
    async fn set_multisig_at_topoheight_for(&mut self, account: &PublicKey, topoheight: u64, multisig: MultiSigPayload) -> Result<(), BlockchainError>;
}

#[async_trait]
impl MultiSigProvider for SledStorage {

    async fn get_multisig_last_topoheight_for(&self, account: &PublicKey) -> Result<Option<u64>, BlockchainError> {
        self.load_optional_from_disk(&self.multisig, account.as_bytes())
    }

    async fn get_multisig_at_topoheight_for(&self, account: &PublicKey, topoheight: u64) -> Result<Option<MultiSigPayload>, BlockchainError> {
        self.load_optional_from_disk(&self.versioned_multisig, &self.get_multisig_key(account, topoheight))
    }

    async fn set_multisig_at_topoheight_for(&mut self, account: &PublicKey, topoheight: u64, multisig: MultiSigPayload) -> Result<(), BlockchainError> {
        let key: [u8; 40] = self.get_multisig_key(account, topoheight);
        self.versioned_multisig.insert(&key, multisig.to_bytes())?;
        Ok(())
    }
}

impl SledStorage {
    // Get the key for the multisig storage
    fn get_multisig_key(&self, account: &PublicKey, topoheight: u64) -> [u8; 40] {
        let mut key = [0; 40];
        key[..32].copy_from_slice(account.as_bytes());
        key[32..].copy_from_slice(&topoheight.to_be_bytes());
        key
    }
}