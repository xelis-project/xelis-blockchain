use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{
    block::{BlockHeader, BlockVersion},
    crypto::Hash,
    difficulty::{
        CumulativeDifficulty,
        Difficulty
    },
    immutable::Immutable,
    time::TimestampMillis,
    varuint::VarUint
};
use crate::core::error::BlockchainError;

// this trait is useful for P2p to check itself the validty of a chain
#[async_trait]
pub trait DifficultyProvider {
    // Get the block height using its hash
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError>;

    // Get the block version using its hash
    async fn get_version_for_block_hash(&self, hash: &Hash) -> Result<BlockVersion, BlockchainError>;

    // Get the timestamp from the block using its hash
    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<TimestampMillis, BlockchainError>;

    // Get the difficulty for a block hash
    async fn get_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError>;

    // Get the cumulative difficulty for a block hash
    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<CumulativeDifficulty, BlockchainError>;

    // Get past blocks (block tips) for a specific block hash
    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Immutable<IndexSet<Hash>>, BlockchainError>;

    // Get a block header using its hash
    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Immutable<BlockHeader>, BlockchainError>;

    // Retrieve the estimated covariance (P) for a block hash
    async fn get_estimated_covariance_for_block_hash(&self, hash: &Hash) -> Result<VarUint, BlockchainError>;
}