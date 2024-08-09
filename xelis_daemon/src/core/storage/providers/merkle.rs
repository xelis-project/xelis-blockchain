use async_trait::async_trait;
use log::trace;
use xelis_common::{crypto::Hash, serializer::Serializer};
use crate::core::{error::{BlockchainError, DiskContext}, storage::SledStorage};

// Merkle Hash provider gives a hash at a specific topoheight.
// The Merkle hash includes only account balances.
// Transactions and block rewards affect account balances.
// Thus, balances are the primary data that needs to be proven.
// NOTE: We use topoheight due to DAG reorgs, as it is the main consensus metric.
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
        self.load_from_disk(&self.merkle_hashes, &topoheight.to_bytes(), DiskContext::BalancesMerkleHashAtTopoHeight)
    }

    async fn set_balances_merkle_hash_at_topoheight(&mut self, topoheight: u64, merkle_proof: &Hash) -> Result<(), BlockchainError> {
        trace!("set merkle hash {} at topoheight {}", merkle_proof, topoheight);
        self.merkle_hashes.insert(&topoheight.to_bytes(), merkle_proof.as_bytes())?;
        Ok(())
    }
}