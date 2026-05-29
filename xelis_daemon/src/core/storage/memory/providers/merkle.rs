use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::{
    error::BlockchainError,
    storage::MerkleHashProvider,
};
use super::super::MemoryStorage;

#[async_trait]
impl MerkleHashProvider for MemoryStorage {
    async fn get_balances_merkle_hash_at_topoheight(&self, _: TopoHeight) -> Result<Hash, BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    async fn set_balances_merkle_hash_at_topoheight(&mut self, _: TopoHeight, _: &Hash) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}
