use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{
    crypto::PublicKey,
    block::TopoHeight,
};
use crate::core::{
    error::BlockchainError,
    storage::{rocksdb::{Account, Column}, AccountProvider, RocksStorage}
};

#[async_trait]
impl AccountProvider for RocksStorage {
    // first time we saw this account on chain
    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        todo!()
    }

    // set the registration topoheight
    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // delete the registration of an account
    async fn delete_account_registration(&mut self, key: &PublicKey) -> Result<(), BlockchainError> {
        todo!()
    }

    // Check if account is registered
    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if account is registered at topoheight
    // This will check that the registration topoheight is less or equal to the given topoheight
    async fn is_account_registered_for_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Delete all registrations at a certain topoheight
    async fn delete_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // Get registered accounts supporting pagination and filtering by topoheight
    // Returned keys must have a nonce or a balance updated in the range given
    async fn get_registered_keys(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<(IndexSet<PublicKey>, usize), BlockchainError> {
        todo!()
    }

    // Check if the account has a nonce updated in the range given
    // It will also check balances if no nonce found
    async fn has_key_updated_in_range(&self, key: &PublicKey, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }
}

impl RocksStorage {
    pub(super) fn get_account_type(&self, key: &PublicKey) -> Result<Account, BlockchainError> {
        self.load_from_disk(Column::Account, key.as_bytes())
    }
}