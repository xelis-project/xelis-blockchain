use std::{collections::{HashMap, HashSet}, sync::Arc};
use async_trait::async_trait;
use xelis_common::{crypto::hash::Hash, block::BlockHeader, config::TIPS_LIMIT};
use crate::core::{error::BlockchainError, blockchain::Blockchain, storage::DifficultyProvider};
use log::error;

struct Data {
    header: Arc<BlockHeader>,
    difficulty: u64,
    cumulative_difficulty: u64
}

pub struct ChainValidator {
    blocks: HashMap<Arc<Hash>, Data>, // include all blocks
    order: Vec<Arc<Hash>> // keep the order of incoming blocks
}

impl ChainValidator {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            order: Vec::new()
        }
    }

    // validate the basic chain structure
    pub async fn insert_block(&mut self, blockchain: &Arc<Blockchain>, hash: Hash, header: BlockHeader) -> Result<(), BlockchainError> {
        if self.blocks.contains_key(&hash) {
            error!("Block {} is already in validator chain!", hash);
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
                if !self.blocks.contains_key(tip) {
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

        // TODO compute POW Hash
        let difficulty = blockchain.verify_proof_of_work(self, &hash, &tips).await?;
        let cumulative_difficulty = 0;

        let hash = Arc::new(hash);
        self.blocks.insert(hash.clone(), Data { header: Arc::new(header), difficulty, cumulative_difficulty });
        self.order.push(hash);

        Ok(())
    }

    fn get_data(&self, hash: &Hash) -> Result<&Data, BlockchainError> {
        self.blocks.get(hash).ok_or_else(|| BlockchainError::BlockNotFound(hash.clone()))
    }

    pub fn get_order(&mut self) -> Vec<Arc<Hash>> {
        let order = std::mem::replace(&mut self.order, Vec::new());
        order
    }

    pub fn consume_block_header(&mut self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        let data = self.blocks.remove(hash).ok_or_else(|| BlockchainError::BlockNotFound(hash.clone()))?;
        Ok(data.header)
    }
}

#[async_trait]
impl DifficultyProvider for ChainValidator {
    async fn get_height_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        Ok(self.get_data(hash)?.header.get_height())
    }

    async fn get_timestamp_for_block(&self, hash: &Hash) -> Result<u128, BlockchainError> {
        Ok(self.get_data(hash)?.header.get_timestamp())
    }

    async fn get_difficulty_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        Ok(self.get_data(hash)?.difficulty)
    }

    async fn get_cumulative_difficulty_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        Ok(self.get_data(hash)?.cumulative_difficulty)
    }

    async fn get_past_blocks_of<'a>(&'a self, hash: &Hash) -> Result<Arc<Vec<Hash>>, BlockchainError> {
        // really dirty
        Ok(Arc::new(self.get_data(hash)?.header.get_tips().clone()))
    }

    async fn get_block_header<'a>(&'a self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        Ok(self.get_data(hash)?.header.clone())
    }
}