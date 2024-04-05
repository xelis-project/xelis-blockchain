use async_trait::async_trait;
use log::trace;
use xelis_common::{crypto::Hash, serializer::Serializer};
use crate::core::{error::BlockchainError, storage::SledStorage};

// Merkle Hash provider allow to give a Hash at a specific topoheight
// The merkle hash only contains account balances
// Because TXs and block rewards are applied on account balances
// Balances are the only thing that needs to be proven
// NOTE: We are based on the topoheight because of DAG reorgs as it's the main consensus
#[async_trait]
pub trait MerkleHashProvider {
    // Get the merkle hash at a specific topoheight
    async fn get_balances_merkle_hash_at_topoheight(&self, topoheight: u64) -> Result<Hash, BlockchainError>;

    // Set the merkle hash at a specific topoheight
    async fn set_balances_merkle_hash_at_topoheight(&mut self, topoheight: u64, merkle_proof: &Hash) -> Result<(), BlockchainError>;
}

#[async_trait]
impl MerkleHashProvider for SledStorage {
    async fn get_balances_merkle_hash_at_topoheight(&self, topoheight: u64) -> Result<Hash, BlockchainError> {
        trace!("get merkle hash at topoheight {}", topoheight);
        self.load_from_disk(&self.merkle_hashes, &topoheight.to_bytes())
    }

    async fn set_balances_merkle_hash_at_topoheight(&mut self, topoheight: u64, merkle_proof: &Hash) -> Result<(), BlockchainError> {
        trace!("set merkle hash {} at topoheight {}", merkle_proof, topoheight);
        self.merkle_hashes.insert(&topoheight.to_bytes(), merkle_proof.as_bytes())?;
        Ok(())
    }
}