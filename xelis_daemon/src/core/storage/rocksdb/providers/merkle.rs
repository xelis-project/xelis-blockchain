use async_trait::async_trait;
use xelis_common::{
    crypto::Hash,
    block::TopoHeight
};
use crate::core::{
    error::BlockchainError,
    storage::{MerkleHashProvider, RocksStorage}
};

// Merkle Hash provider allow to give a Hash at a specific topoheight
// The merkle hash only contains account balances
// Because TXs and block rewards are applied on account balances
// Balances are the only thing that needs to be proven
// NOTE: We are based on the topoheight because of DAG reorgs as it's the main consensus
#[async_trait]
impl MerkleHashProvider for RocksStorage {
    // Get the merkle hash at a specific topoheight
    async fn get_balances_merkle_hash_at_topoheight(&self, _: TopoHeight) -> Result<Hash, BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    // Set the merkle hash at a specific topoheight
    async fn set_balances_merkle_hash_at_topoheight(&mut self, _: TopoHeight, _: &Hash) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}