use std::sync::Arc;

use async_trait::async_trait;
use xelis_common::{block::BlockHeader, crypto::hash::Hash};

use crate::core::error::BlockchainError;

use super::{SledStorage, Storage};


// this trait is useful for P2p to check itself the validty of a chain
#[async_trait]
pub trait DifficultyProvider {
    async fn get_height_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError>;
    async fn get_timestamp_for_block(&self, hash: &Hash) -> Result<u128, BlockchainError>;
    async fn get_difficulty_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError>;
    async fn get_cumulative_difficulty_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError>;
    async fn get_past_blocks_of<'a>(&'a self, hash: &Hash) -> Result<Arc<Vec<Hash>>, BlockchainError>;
    async fn get_block_header<'a>(&'a self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError>;
}

#[async_trait]
impl DifficultyProvider for SledStorage {
    async fn get_height_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        self.get_height_for_block_hash(hash).await
    }

    async fn get_timestamp_for_block(&self, hash: &Hash) -> Result<u128, BlockchainError> {
        self.get_timestamp_for_block_hash(hash).await
    }

    async fn get_difficulty_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        self.get_difficulty_for_block_hash(hash)
    }

    async fn get_cumulative_difficulty_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        self.get_cumulative_difficulty_for_block_hash(hash).await
    }

    async fn get_past_blocks_of<'a>(&'a self, hash: &Hash) -> Result<Arc<Vec<Hash>>, BlockchainError> {
        self.get_past_blocks_for_block_hash(hash).await
    }

    async fn get_block_header<'a>(&'a self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        self.get_block_header_by_hash(hash).await
    }
}