use async_trait::async_trait;
use indexmap::IndexSet;
use log::trace;
use xelis_common::{
    block::BlockHeader,
    crypto::Hash,
    difficulty::{
        CumulativeDifficulty,
        Difficulty
    },
    immutable::Immutable,
    time::TimestampMillis,
    varuint::VarUint
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{DifficultyProvider, SledStorage},
};

#[async_trait]
impl DifficultyProvider for SledStorage {
    // TODO optimize all these functions to read only what is necessary
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        trace!("get height for block hash {}", hash);
        let block = self.get_block_header_by_hash(hash).await?;
        Ok(block.get_height())
    }

    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<TimestampMillis, BlockchainError> {
        trace!("get timestamp for hash {}", hash);
        let block = self.get_block_header_by_hash(hash).await?;
        Ok(block.get_timestamp())
    }

    async fn get_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError> {
        trace!("get difficulty for hash {}", hash);
        self.load_from_disk(&self.difficulty, hash.as_bytes(), DiskContext::DifficultyForBlockHash)
    }

    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<CumulativeDifficulty, BlockchainError> {
        trace!("get cumulative difficulty for hash {}", hash);
        self.get_cacheable_data(&self.cumulative_difficulty, &self.cumulative_difficulty_cache, hash, DiskContext::CumulativeDifficultyForBlockHash).await
    }

    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Immutable<IndexSet<Hash>>, BlockchainError> {
        trace!("get past blocks of {}", hash);
        let block = self.get_block_header_by_hash(hash).await?;
        Ok(block.get_immutable_tips().clone())
    }

    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Immutable<BlockHeader>, BlockchainError> {
        trace!("get block by hash: {}", hash);
        self.get_cacheable_arc_data(&self.blocks, &self.blocks_cache, hash, DiskContext::GetBlockHeaderByHash).await
    }

    async fn get_estimated_covariance_for_block_hash(&self, hash: &Hash) -> Result<VarUint, BlockchainError> {
        trace!("get p for hash {}", hash);
        self.load_from_disk(&self.difficulty_covariance, hash.as_bytes(), DiskContext::EstimatedCovarianceForBlockHash)
    }
}