use std::borrow::Cow;

use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
    serializer::Serializer,
    transaction::MultiSigPayload
};

use crate::core::{
    error::BlockchainError,
    storage::{Versioned, SledStorage}
};

pub type VersionedMultiSig<'a> = Versioned<Option<Cow<'a, MultiSigPayload>>>;

#[async_trait]
pub trait MultiSigProvider {
    // Retrieve the last topoheight for a given account
    async fn get_multisig_last_topoheight_for(&self, account: &PublicKey) -> Result<Option<TopoHeight>, BlockchainError>;

    // Retrieve a multisig setup for a given account
    async fn get_multisig_at_topoheight_for<'a>(&'a self, account: &PublicKey, topoheight: TopoHeight) -> Result<Option<VersionedMultiSig<'a>>, BlockchainError>;

    // Store a multisig setup for a given account
    async fn set_multisig_at_topoheight_for<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError>;

    // Retrieve the multisig setup at the maximum topoheight for a given account
    async fn get_multisig_at_maximum_topoheight_for<'a>(&'a self, account: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedMultiSig<'a>)>, BlockchainError>;
}

#[async_trait]
impl MultiSigProvider for SledStorage {
    async fn get_multisig_last_topoheight_for(&self, account: &PublicKey) -> Result<Option<TopoHeight>, BlockchainError> {
        self.load_optional_from_disk(&self.multisig, account.as_bytes())
    }

    async fn get_multisig_at_topoheight_for<'a>(&'a self, account: &PublicKey, topoheight: TopoHeight) -> Result<Option<VersionedMultiSig<'a>>, BlockchainError> {
        self.load_optional_from_disk(&self.versioned_multisig, &self.get_multisig_key(account, topoheight))
    }

    async fn set_multisig_at_topoheight_for<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError> {
        let key: [u8; 40] = self.get_multisig_key(account, topoheight);
        self.versioned_multisig.insert(&key, multisig.to_bytes())?;
        Ok(())
    }

    async fn get_multisig_at_maximum_topoheight_for<'a>(&'a self, account: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedMultiSig<'a>)>, BlockchainError> {
        let Some(topoheight) = self.get_multisig_last_topoheight_for(account).await? else {
            return Ok(None)
        };

        let mut version = self.get_multisig_at_topoheight_for(account, topoheight).await?
            .ok_or(BlockchainError::VersionedNotFound)?;

        if topoheight <= maximum_topoheight {
            return Ok(Some((topoheight, version)))
        }

        while let Some(topoheight) = version.get_previous_topoheight() {
            if topoheight <= maximum_topoheight {
                return Ok(Some((topoheight, version)))
            }

            version = self.get_multisig_at_topoheight_for(account, topoheight).await?
                .ok_or(BlockchainError::VersionedNotFound)?;
        }

        Ok(None)
    }
}

impl SledStorage {
    // Get the key for the multisig storage
    fn get_multisig_key(&self, account: &PublicKey, topoheight: TopoHeight) -> [u8; 40] {
        let mut key = [0; 40];
        key[..32].copy_from_slice(account.as_bytes());
        key[32..].copy_from_slice(&topoheight.to_be_bytes());
        key
    }
}