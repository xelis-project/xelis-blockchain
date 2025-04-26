use std::sync::Arc;

use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{block::BlockHeader, crypto::Hash, difficulty::{CumulativeDifficulty, Difficulty}, immutable::Immutable, time::TimestampMillis, varuint::VarUint};
use crate::core::{error::BlockchainError, storage::{DifficultyProvider, RocksStorage}};

#[async_trait]
impl DifficultyProvider for RocksStorage {
    // Get the block height using its hash
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        Ok(todo!())
    }

    // Get the timestamp from the block using its hash
    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<TimestampMillis, BlockchainError> {
        Ok(todo!())
    }

    // Get the difficulty for a block hash
    async fn get_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError> {
        Ok(todo!())
    }

    // Get the cumulative difficulty for a block hash
    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<CumulativeDifficulty, BlockchainError> {
        Ok(todo!())
    }

    // Get past blocks (block tips) for a specific block hash
    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Immutable<IndexSet<Hash>>, BlockchainError> {
        Ok(todo!())
    }

    // Get a block header using its hash
    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        Ok(todo!())
    }

    // Retrieve the estimated covariance (P) for a block hash
    async fn get_estimated_covariance_for_block_hash(&self, hash: &Hash) -> Result<VarUint, BlockchainError> {
        Ok(todo!())
    }
}