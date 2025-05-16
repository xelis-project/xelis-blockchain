use async_trait::async_trait;
use xelis_common::{
    account::VersionedNonce,
    block::TopoHeight,
    crypto::PublicKey
};
use crate::core::error::BlockchainError;

#[async_trait]
pub trait NonceProvider {
    // Check if the account has a nonce
    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError>;

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

    // set the new nonce at exact topoheight for account
    // This will do like `set_nonce_at_topoheight` but will also update the pointer
    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: TopoHeight, nonce: &VersionedNonce) -> Result<(), BlockchainError>;
}