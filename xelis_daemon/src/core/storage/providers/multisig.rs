use std::borrow::Cow;

use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
    serializer::Serializer,
    transaction::MultiSigPayload
};

use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{SledStorage, Versioned}
};

pub type VersionedMultiSig<'a> = Versioned<Option<Cow<'a, MultiSigPayload>>>;

#[async_trait]
pub trait MultiSigProvider {
    // Retrieve the last topoheight for a given account
    async fn get_last_topoheight_for_multisig(&self, account: &PublicKey) -> Result<Option<TopoHeight>, BlockchainError>;

    // Retrieve a multisig setup for a given account
    async fn get_multisig_at_topoheight_for<'a>(&'a self, account: &PublicKey, topoheight: TopoHeight) -> Result<VersionedMultiSig<'a>, BlockchainError>;

    // Store a multisig setup for a given account
    async fn set_multisig_at_topoheight_for<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError>;

    // Delete the last topoheight for a given account
    async fn delete_last_topoheight_for_multisig(&mut self, account: &PublicKey) -> Result<(), BlockchainError>;

    // Retrieve the multisig setup at the maximum topoheight for a given account
    async fn get_multisig_at_maximum_topoheight_for<'a>(&'a self, account: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedMultiSig<'a>)>, BlockchainError>;

    // Verify if an account has a multisig setup
    // If the latest version is None, the account has no multisig setup
    async fn has_multisig(&self, account: &PublicKey) -> Result<bool, BlockchainError>;

    // Verify if an account has a multisig setup at a given topoheight
    // If the version is None, it returns None
    async fn has_multisig_at_topoheight(&self, account: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Retrieve the last multisig setup for a given account
    async fn get_last_multisig<'a>(&'a self, account: &PublicKey) -> Result<(TopoHeight, VersionedMultiSig<'a>), BlockchainError> {
        let topoheight = self.get_last_topoheight_for_multisig(account).await?
            .ok_or(BlockchainError::NoMultisig)?;

        let state = self.get_multisig_at_topoheight_for(account, topoheight).await?;

        Ok((topoheight, state))
    }

    // Store the last topoheight for a given account
    async fn set_last_topoheight_for_multisig<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Store the last multisig setup for a given account
    async fn set_last_multisig_to<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError>;
}

#[async_trait]
impl MultiSigProvider for SledStorage {
    async fn get_last_topoheight_for_multisig(&self, account: &PublicKey) -> Result<Option<TopoHeight>, BlockchainError> {
        self.load_optional_from_disk(&self.multisig, account.as_bytes())
    }

    async fn get_multisig_at_topoheight_for<'a>(&'a self, account: &PublicKey, topoheight: TopoHeight) -> Result<VersionedMultiSig<'a>, BlockchainError> {
        self.load_from_disk(&self.versioned_multisigs, &self.get_multisig_key(account, topoheight), DiskContext::Multisig )
    }

    async fn set_multisig_at_topoheight_for<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError> {
        let key: [u8; 40] = self.get_multisig_key(account, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_multisigs, &key, multisig.to_bytes())?;
        Ok(())
    }

    async fn delete_last_topoheight_for_multisig(&mut self, account: &PublicKey) -> Result<(), BlockchainError> {
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.multisig, account.as_bytes())?;
        Ok(())
    }

    async fn get_multisig_at_maximum_topoheight_for<'a>(&'a self, account: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedMultiSig<'a>)>, BlockchainError> {
        let Some(topoheight) = self.get_last_topoheight_for_multisig(account).await? else {
            return Ok(None)
        };

        let mut version = self.get_multisig_at_topoheight_for(account, topoheight).await?;

        if topoheight <= maximum_topoheight {
            return Ok(Some((topoheight, version)))
        }

        while let Some(topoheight) = version.get_previous_topoheight() {
            if topoheight <= maximum_topoheight {
                return Ok(Some((topoheight, version)))
            }

            version = self.get_multisig_at_topoheight_for(account, topoheight).await?;
        }

        Ok(None)
    }

    async fn has_multisig(&self, account: &PublicKey) -> Result<bool, BlockchainError> {
        let Some(topoheight) = self.get_last_topoheight_for_multisig(account).await? else {
            return Ok(false)
        };

        let version = self.get_multisig_at_topoheight_for(account, topoheight).await?;
        Ok(version.get().is_some())
    }

    async fn has_multisig_at_topoheight(&self, account: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let version = self.get_multisig_at_topoheight_for(account, topoheight).await?;
        Ok(version.get().is_some())
    }

    async fn set_last_topoheight_for_multisig<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        Self::insert_into_disk(self.snapshot.as_mut(), &self.multisig, account.as_bytes(), &topoheight.to_be_bytes())?;
        Ok(())
    }

    async fn set_last_multisig_to<'a>(&mut self, account: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError> {
        self.set_multisig_at_topoheight_for(account, topoheight, multisig).await?;
        self.set_last_topoheight_for_multisig(account, topoheight).await?;
        Ok(())
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