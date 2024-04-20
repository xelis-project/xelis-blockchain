use std::sync::Arc;
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
    serializer::Serializer,
    time::TimestampMillis,
    varuint::VarUint
};
use crate::core::{
    error::BlockchainError,
    storage::SledStorage,
};

// this trait is useful for P2p to check itself the validty of a chain
#[async_trait]
pub trait DifficultyProvider {
    // Get the block height using its hash
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError>;

    // Get the timestamp from the block using its hash
    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<TimestampMillis, BlockchainError>;

    // Get the difficulty for a block hash
    async fn get_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError>;

    // Get the cumulative difficulty for a block hash
    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<CumulativeDifficulty, BlockchainError>;

    // Get past blocks (block tips) for a specific block hash
    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Immutable<IndexSet<Hash>>, BlockchainError>;

    // Get a block header using its hash
    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError>;

    // Retrieve the estimated covariance (P) for a block hash
    async fn get_estimated_covariance_for_block_hash(&self, hash: &Hash) -> Result<VarUint, BlockchainError>;

    // Set the estimated covariance (P) for a block hash
    async fn set_estimated_covariance_for_block_hash(&mut self, hash: &Hash, p: VarUint) -> Result<(), BlockchainError>;

    // Set the cumulative difficulty for a block hash
    async fn set_cumulative_difficulty_for_block_hash(&mut self, hash: &Hash, cumulative_difficulty: CumulativeDifficulty) -> Result<(), BlockchainError>;
}

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
        self.load_from_disk(&self.difficulty, hash.as_bytes())
    }

    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<CumulativeDifficulty, BlockchainError> {
        trace!("get cumulative difficulty for hash {}", hash);
        self.get_cacheable_data(&self.cumulative_difficulty, &self.cumulative_difficulty_cache, hash).await
    }

    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Immutable<IndexSet<Hash>>, BlockchainError> {
        trace!("get past blocks of {}", hash);
        let tips = if let Some(cache) = &self.past_blocks_cache {
            let mut cache = cache.lock().await;
            if let Some(tips) = cache.get(hash) {
                return Ok(Immutable::Arc(tips.clone()))
            }
    
            let block = self.get_block_header_by_hash(hash).await?;
        
            let tips = Arc::new(block.get_tips().clone());
            cache.put(hash.clone(), tips.clone());
            Immutable::Arc(tips)
        } else {
            let block = self.get_block_header_by_hash(hash).await?;
            Immutable::Owned(block.get_tips().clone())
        };

        Ok(tips)
    }

    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        trace!("get block by hash: {}", hash);
        self.get_cacheable_arc_data(&self.blocks, &self.blocks_cache, hash).await
    }

    async fn set_cumulative_difficulty_for_block_hash(&mut self, hash: &Hash, cumulative_difficulty: CumulativeDifficulty) -> Result<(), BlockchainError> {
        trace!("set cumulative difficulty for hash {}", hash);
        self.cumulative_difficulty.insert(hash.as_bytes(), cumulative_difficulty.to_bytes())?;
        Ok(())
    }

    async fn get_estimated_covariance_for_block_hash(&self, hash: &Hash) -> Result<VarUint, BlockchainError> {
        trace!("get p for hash {}", hash);
        self.load_from_disk(&self.difficulty_covariance, hash.as_bytes())
    }

    async fn set_estimated_covariance_for_block_hash(&mut self, hash: &Hash, p: VarUint) -> Result<(), BlockchainError> {
        trace!("set p for hash {}", hash);
        self.difficulty_covariance.insert(hash.as_bytes(), p.to_bytes())?;
        Ok(())
    }
}