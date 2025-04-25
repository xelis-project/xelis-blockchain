use std::borrow::Cow;

use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
    transaction::MultiSigPayload,
    versioned_type::{State, Versioned}
};
use crate::core::error::BlockchainError;

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

    // Get all the multisig setups for a given set of keys
    async fn get_updated_multisigs(&self, keys: &IndexSet<PublicKey>, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<Vec<State<MultiSigPayload>>, BlockchainError>;

    // Verify if an account has a multisig setup
    // If the latest version is None, the account has no multisig setup
    async fn has_multisig(&self, account: &PublicKey) -> Result<bool, BlockchainError>;

    // Verify if an account has a multisig setup at a given topoheight
    // If the version is None, it returns None
    async fn has_multisig_at_topoheight(&self, account: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Verify if a version exists at a given topoheight
    async fn has_multisig_at_exact_topoheight(&self, account: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

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