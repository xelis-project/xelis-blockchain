use std::sync::Arc;
use async_trait::async_trait;
use indexmap::{IndexMap, IndexSet};
use xelis_common::{
    block::BlockHeader,
    config::TIPS_LIMIT,
    crypto::hash::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable
};
use crate::core::{
    error::BlockchainError,
    blockchain::Blockchain,
    storage::{DifficultyProvider, Storage}
};
use log::{error, trace};

// This struct is used to store the block data in the chain validator
struct BlockData {
    header: Arc<BlockHeader>,
    difficulty: Difficulty,
    cumulative_difficulty: CumulativeDifficulty
}

// Chain validator is used to validate the blocks received from the network
// We store the blocks in topological order and we verify the proof of work validity
// This is doing only minimal checks and valid chain order based on topoheight and difficulty
pub struct ChainValidator<'a, S: Storage> {
    // store all blocks data in topological order
    blocks: IndexMap<Hash, BlockData>,
    // Blockchain reference used to verify current chain state
    blockchain: &'a Blockchain<S>
}

impl<'a, S: Storage> ChainValidator<'a, S> {
    pub fn new(blockchain: &'a Blockchain<S>) -> Self {
        Self {
            blocks: IndexMap::new(),
            blockchain
        }
    }

    // validate the basic chain structure
    // We expect that the block added is the next block ordered by topoheight
    pub async fn insert_block(&mut self, hash: Hash, header: BlockHeader) -> Result<(), BlockchainError> {
        trace!("Inserting block {} into chain validator", hash);

        if self.blocks.contains_key(&hash) {
            error!("Block {} is already in validator chain!", hash);
            return Err(BlockchainError::AlreadyInChain)
        }

        if self.blockchain.has_block(&hash).await? {
            error!("Block {} is already in blockchain!", hash);
            return Err(BlockchainError::AlreadyInChain)
        }

        let tips = header.get_tips();
        let tips_count = tips.len();
        
        // verify tips count
        if tips_count == 0 || tips_count > TIPS_LIMIT {
            error!("Block {} contains {} tips while only {} is accepted", hash, tips_count, TIPS_LIMIT);
            return Err(BlockchainError::InvalidTips)
        }

        // verify that we have already all its tips
        {
            for tip in tips {
                trace!("Checking tip {} for block {}", tip, hash);
                if !self.blocks.contains_key(tip) && !self.blockchain.has_block(tip).await? {
                    error!("Block {} contains tip {} which is not present in chain validator", hash, tip);
                    return Err(BlockchainError::InvalidTips)
                }
            }
        }

        let pow_hash = header.get_pow_hash();
        trace!("POW hash: {}", pow_hash);
        let difficulty = self.blockchain.verify_proof_of_work(self, &pow_hash, tips.iter()).await?;
        // TODO FIXME
        let cumulative_difficulty = CumulativeDifficulty::zero();

        self.blocks.insert(hash, BlockData { header: Arc::new(header), difficulty, cumulative_difficulty });

        Ok(())
    }

    // Retrieve all blocks from the chain validator
    pub fn get_blocks(self) -> impl Iterator<Item = (Hash, Arc<BlockHeader>)> {
        self.blocks.into_iter().map(|(hash, data)| (hash, data.header))
    }
}

#[async_trait]
impl<S: Storage> DifficultyProvider for ChainValidator<'_, S> {
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            return Ok(data.header.get_height())
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_height_for_block_hash(hash).await?)
    }

    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<u128, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            return Ok(data.header.get_timestamp())
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_timestamp_for_block_hash(hash).await?)
    }

    async fn get_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            return Ok(data.difficulty)
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_difficulty_for_block_hash(hash).await?)
    }

    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<CumulativeDifficulty, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            return Ok(data.cumulative_difficulty)
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_cumulative_difficulty_for_block_hash(hash).await?)
    }

    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Immutable<IndexSet<Hash>>, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            return Ok(Immutable::Owned(data.header.get_tips().clone()))
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_past_blocks_for_block_hash(hash).await?)
    }

    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            return Ok(data.header.clone())
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_block_header_by_hash(hash).await?)
    }
}