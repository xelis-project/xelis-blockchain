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
    blockchain::Blockchain,
    error::BlockchainError,
    storage::{DagOrderProvider, DifficultyProvider, Storage}
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
    blockchain: &'a Blockchain<S>,
    // This is used to compute the expected topoheight of each new block
    // It must be 1 topoheight above the common point
    starting_topoheight: u64,
    // Cache to prevent searching it multiple times
    // it is used to find the cumulative difficulty for each block
    stable_hash: Hash
}

impl<'a, S: Storage> ChainValidator<'a, S> {
    pub async fn new(blockchain: &'a Blockchain<S>, starting_topoheight: u64) -> Result<Self, BlockchainError> {        
        // Retrieve the stable hash
        let stable_hash = {
            let stable_topo = blockchain.get_stable_topoheight();
            let storage = blockchain.get_storage().read().await;
            storage.get_hash_at_topo_height(stable_topo).await?
        };

        Ok(Self {
            blocks: IndexMap::new(),
            blockchain,
            starting_topoheight,
            stable_hash
        })
    }

    // Check if the chain validator has a higher cumulative difficulty than our blockchain
    // This is used to determine if we should switch to the new chain by popping blocks or not
    pub async fn has_higher_cumulative_difficulty(&self) -> Result<bool, BlockchainError> {
        let new_cumulative_difficulty = self.get_chain_cumulative_difficulty().ok_or(BlockchainError::NotEnoughBlocks)?;

        // Retrieve the current cumulative difficulty
        let current_cumulative_difficulty = {
            let storage = self.blockchain.get_storage().read().await;
            let top_block_hash = self.blockchain.get_top_block_hash_for_storage(&storage).await?;
            storage.get_cumulative_difficulty_for_block_hash(&top_block_hash).await?
        };

        Ok(*new_cumulative_difficulty > current_cumulative_difficulty)
    }

    // Retrieve the cumulative difficulty of the chain validator
    // It is the cumulative difficulty of the last block added
    pub fn get_chain_cumulative_difficulty(&self) -> Option<&CumulativeDifficulty> {
        self.blocks.last().map(|(_, data)| &data.cumulative_difficulty)
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

        // Find the cumulative difficulty for this block
        let (_, cumulative_difficulty) = self.blockchain.find_tip_work_score(self, &hash, &self.stable_hash, self.blockchain.get_stable_height()).await?;

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

#[async_trait]
impl<S: Storage> DagOrderProvider for ChainValidator<'_, S> {
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        if let Some(index) = self.blocks.get_index_of(hash) {
            return Ok(self.starting_topoheight + index as u64)
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_topo_height_for_hash(hash).await?)
    }

    // This should never happen in our case
    async fn set_topo_height_for_block(&mut self, _: &Hash, _: u64) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    async fn is_block_topological_ordered(&self, hash: &Hash) -> bool {
        if self.blocks.contains_key(hash) {
            return true
        }

        let storage = self.blockchain.get_storage().read().await;
        storage.is_block_topological_ordered(hash).await
    }

    async fn get_hash_at_topo_height(&self, topoheight: u64) -> Result<Hash, BlockchainError> {
        if topoheight >= self.starting_topoheight {
            let index = (topoheight - self.starting_topoheight) as usize;
            return self.blocks.get_index(index).map(|(hash, _)| hash.clone()).ok_or(BlockchainError::BlockNotOrdered);
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_hash_at_topo_height(topoheight).await?)
    }
}