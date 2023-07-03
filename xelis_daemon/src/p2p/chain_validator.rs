use std::{collections::{HashMap, HashSet}, sync::Arc};
use async_trait::async_trait;
use xelis_common::{crypto::hash::Hash, block::{BlockHeader, Difficulty}, config::TIPS_LIMIT};
use crate::core::{error::BlockchainError, blockchain::Blockchain, storage::{DifficultyProvider, Storage}};
use log::{error, trace};

struct Data {
    header: Arc<BlockHeader>,
    difficulty: Difficulty,
    cumulative_difficulty: Difficulty
}

pub struct ChainValidator<S: Storage> {
    blocks: HashMap<Arc<Hash>, Data>, // include all blocks
    order: Vec<Arc<Hash>>, // keep the order of incoming blocks
    blockchain: Arc<Blockchain<S>>
}

impl<S: Storage> ChainValidator<S> {
    pub fn new(blockchain: Arc<Blockchain<S>>) -> Self {
        Self {
            blocks: HashMap::new(),
            order: Vec::new(),
            blockchain
        }
    }

    // validate the basic chain structure
    pub async fn insert_block(&mut self, hash: Hash, header: BlockHeader) -> Result<(), BlockchainError> {
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

        // verify that we have already all its tips & that they are all unique
        {
            let mut unique_tips = HashSet::with_capacity(tips_count);
            for tip in tips {
                trace!("Checking tip {} for block {}", tip, hash);
                if !self.blocks.contains_key(tip) && !self.blockchain.has_block(tip).await? {
                    error!("Block {} contains tip {} which is not present in chain validator", hash, tip);
                    return Err(BlockchainError::InvalidTips)
                }

                if unique_tips.contains(tip) {
                    error!("Block {} contains a duplicated tip {}!", hash, tip);
                    return Err(BlockchainError::InvalidTips)
                }

                unique_tips.insert(tip);
            }
        }

        let pow_hash = header.get_pow_hash();
        trace!("POW hash: {}", pow_hash);
        let difficulty = self.blockchain.verify_proof_of_work(self, &pow_hash, &tips).await?;
        let cumulative_difficulty = 0;

        let hash = Arc::new(hash);
        self.blocks.insert(hash.clone(), Data { header: Arc::new(header), difficulty, cumulative_difficulty });
        self.order.push(hash);

        Ok(())
    }

    // retrieve the whole chain order maintained internally
    pub fn get_order(&mut self) -> Vec<Arc<Hash>> {
        let order = std::mem::replace(&mut self.order, Vec::new());
        order
    }

    // used in P2P to retrieve the BlockHeader instead of doing a Copy of it
    pub fn consume_block_header(&mut self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        let data = self.blocks.remove(hash).ok_or_else(|| BlockchainError::BlockNotFound(hash.clone()))?;
        Ok(data.header)
    }
}

#[async_trait]
impl<S: Storage> DifficultyProvider for ChainValidator<S> {
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

    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            return Ok(data.cumulative_difficulty)
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_cumulative_difficulty_for_block_hash(hash).await?)
    }

    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Arc<Vec<Hash>>, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            // Dirty pls help me
            return Ok(Arc::new(data.header.get_tips().clone()))
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