use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{
    block::BlockHeader,
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    time::TimestampMillis,
    varuint::VarUint
};
use crate::core::{
    error::BlockchainError,
    storage::{
        BlockDifficulty,
        Column,
        DifficultyProvider,
        RocksStorage
    }
};

#[async_trait]
impl DifficultyProvider for RocksStorage {
    // Get the block height using its hash
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        let header = self.get_block_header_by_hash(hash).await?;
        Ok(header.get_height())
    }

    // Get the timestamp from the block using its hash
    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<TimestampMillis, BlockchainError> {
        let header = self.get_block_header_by_hash(hash).await?;
        Ok(header.get_timestamp())
    }

    // Get the difficulty for a block hash
    async fn get_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError> {
        let block_difficulty: BlockDifficulty = self.load_from_disk(Column::BlockDifficulty, hash)?;
        Ok(block_difficulty.difficulty)
    }

    // Get the cumulative difficulty for a block hash
    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<CumulativeDifficulty, BlockchainError> {
        let block_difficulty: BlockDifficulty = self.load_from_disk(Column::BlockDifficulty, hash)?;
        Ok(block_difficulty.cumulative_difficulty)
    }

    // Get past blocks (block tips) for a specific block hash
    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Immutable<IndexSet<Hash>>, BlockchainError> {
        let header = self.get_block_header_by_hash(hash).await?;
        Ok(Immutable::Owned(header.get_tips().clone()))
    }

    // Get a block header using its hash
    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Immutable<BlockHeader>, BlockchainError> {
        let header: BlockHeader = self.load_from_disk(Column::Blocks, hash)?;
        Ok(Immutable::Owned(header))
    }

    // Retrieve the estimated covariance (P) for a block hash
    async fn get_estimated_covariance_for_block_hash(&self, hash: &Hash) -> Result<VarUint, BlockchainError> {
        let block_difficulty: BlockDifficulty = self.load_from_disk(Column::BlockDifficulty, hash)?;
        Ok(block_difficulty.covariance)
    }
}