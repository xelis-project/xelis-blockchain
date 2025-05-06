use async_trait::async_trait;
use xelis_common::{
    account::VersionedNonce,
    block::TopoHeight,
    crypto::PublicKey
};
use crate::core::{error::BlockchainError, storage::{NonceProvider, RocksStorage}};

#[async_trait]
impl NonceProvider for RocksStorage {
    // Check if the account has a nonce
    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Get the number of accounts with nonces available on chain
    async fn count_accounts(&self) -> Result<u64, BlockchainError> {
        todo!()
    }

    // Check if the account has a nonce at a specific topoheight
    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Get the last topoheigh that the account has a nonce
    async fn get_last_topoheight_for_nonce(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        todo!()
    }

    // Get the last nonce of the account, this is based on the last topoheight available
    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(TopoHeight, VersionedNonce), BlockchainError> {
        todo!()
    }

    // Get the nonce at a specific topoheight for an account
    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<VersionedNonce, BlockchainError> {
        todo!()
    }

    // Get the nonce under or equal topoheight requested for an account
    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedNonce)>, BlockchainError> {
        todo!()
    }

    // Set the last topoheight that the account has a nonce changed
    async fn set_last_topoheight_for_nonce(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // Delete the last topoheight that the account has a nonce
    // This is only removing the pointer, not the version itself
    async fn delete_last_topoheight_for_nonce(&mut self, key: &PublicKey) -> Result<(), BlockchainError> {
        todo!()
    }

    // set the new nonce at exact topoheight for account
    // This will do like `set_nonce_at_topoheight` but will also update the pointer
    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: TopoHeight, nonce: &VersionedNonce) -> Result<(), BlockchainError> {
        todo!()
    }

    // set a new nonce at specific topoheight for account
    async fn set_nonce_at_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight, version: &VersionedNonce) -> Result<(), BlockchainError> {
        todo!()
    }
}