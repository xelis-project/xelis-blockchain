use std::sync::Arc;
use async_trait::async_trait;
use indexmap::{IndexMap, IndexSet};
use xelis_common::{
    block::BlockHeader,
    config::TIPS_LIMIT,
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
    blockchain::Blockchain,
    blockdag,
    error::BlockchainError,
    storage::{
        BlocksAtHeightProvider,
        DagOrderProvider,
        DifficultyProvider,
        MerkleHashProvider,
        PrunedTopoheightProvider,
        Storage,
        Tips
    }
};
use log::{debug, trace};

// This struct is used to store the block data in the chain validator
struct BlockData {
    header: Arc<BlockHeader>,
    difficulty: Difficulty,
    cumulative_difficulty: CumulativeDifficulty,
    p: VarUint
}

// Chain validator is used to validate the blocks received from the network
// We store the blocks in topological order and we verify the proof of work validity
// This is doing only minimal checks and valid chain order based on topoheight and difficulty
pub struct ChainValidator<'a, S: Storage> {
    // store all blocks data in topological order
    blocks: IndexMap<Hash, BlockData>,
    // store all blocks hashes at a specific height
    blocks_at_height: IndexMap<u64, Tips>,
    // Blockchain reference used to verify current chain state
    blockchain: &'a Blockchain<S>,
    // This is used to compute the expected topoheight of each new block
    // It must be 1 topoheight above the common point
    starting_topoheight: u64,
}

impl<'a, S: Storage> ChainValidator<'a, S> {
    // Starting topoheight must be 1 topoheight above the common point
    pub fn new(blockchain: &'a Blockchain<S>, starting_topoheight: u64) -> Self {        
        Self {
            blocks: IndexMap::new(),
            blocks_at_height: IndexMap::new(),
            blockchain,
            starting_topoheight
        }
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
            debug!("Block {} is already in validator chain!", hash);
            return Err(BlockchainError::AlreadyInChain)
        }

        if self.blockchain.has_block(&hash).await? {
            debug!("Block {} is already in blockchain!", hash);
            return Err(BlockchainError::AlreadyInChain)
        }

        let tips = header.get_tips();
        let tips_count = tips.len();
        
        // verify tips count
        if tips_count == 0 || tips_count > TIPS_LIMIT {
            debug!("Block {} contains {} tips while only {} is accepted", hash, tips_count, TIPS_LIMIT);
            return Err(BlockchainError::InvalidTipsCount(hash, tips_count))
        }

        // verify that we have already all its tips
        {
            for tip in tips {
                trace!("Checking tip {} for block {}", tip, hash);
                if !self.blocks.contains_key(tip) && !self.blockchain.has_block(tip).await? {
                    debug!("Block {} contains tip {} which is not present in chain validator", hash, tip);
                    return Err(BlockchainError::InvalidTipsNotFound(hash, tip.clone()))
                }
            }
        }

        // Verify the block height by tips
        {
            let height_by_tips = blockdag::calculate_height_at_tips(self, header.get_tips().iter()).await?;
            if height_by_tips != header.get_height() {
                debug!("Block {} has height {} while expected height is {}", hash, header.get_height(), height_by_tips);
                return Err(BlockchainError::InvalidBlockHeight(height_by_tips, header.get_height()))
            }
        }

        let pow_hash = header.get_pow_hash()?;
        trace!("POW hash: {}", pow_hash);
        let (difficulty, p) = self.blockchain.verify_proof_of_work(self, &pow_hash, tips.iter()).await?;

        // Find the common base between the block and the current blockchain
        let (base, base_height) = self.blockchain.find_common_base(self, header.get_tips()).await?;

        // Find the cumulative difficulty for this block
        let (_, cumulative_difficulty) = self.blockchain.find_tip_work_score(self, &hash, &base, base_height).await?;

        // Store the block in both maps
        // One is for blocks at height and the other is for the block data
        self.blocks_at_height.entry(header.get_height()).or_insert_with(Tips::new).insert(hash.clone());
        self.blocks.insert(hash, BlockData { header: Arc::new(header), difficulty, cumulative_difficulty, p });

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

    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<TimestampMillis, BlockchainError> {
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

    async fn get_estimated_covariance_for_block_hash(&self, hash: &Hash) -> Result<VarUint, BlockchainError> {
        if let Some(data) = self.blocks.get(hash) {
            return Ok(data.p.clone())
        }

        let storage = self.blockchain.get_storage().read().await;
        Ok(storage.get_estimated_covariance_for_block_hash(hash).await?)
    }

    async fn set_estimated_covariance_for_block_hash(&mut self, _: &Hash, _: VarUint) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    async fn set_cumulative_difficulty_for_block_hash(&mut self, _: &Hash, _: CumulativeDifficulty) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
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

#[async_trait]
impl<S: Storage> BlocksAtHeightProvider for ChainValidator<'_, S> {
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError> {
        if self.blocks_at_height.contains_key(&height) {
            return Ok(true)
        }

        let storage = self.blockchain.get_storage().read().await;
        storage.has_blocks_at_height(height).await
    }

    // Retrieve the blocks hashes at a specific height
    async fn get_blocks_at_height(&self, height: u64) -> Result<Tips, BlockchainError> {
        if let Some(tips) = self.blocks_at_height.get(&height) {
            return Ok(tips.clone())
        }

        let storage = self.blockchain.get_storage().read().await;
        storage.get_blocks_at_height(height).await
    }

    // This is used to store the blocks hashes at a specific height
    async fn set_blocks_at_height(&self, _: Tips, _: u64) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    // Append a block hash at a specific height
    async fn add_block_hash_at_height(&mut self, _: Hash, _: u64) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    // Remove a block hash at a specific height
    async fn remove_block_hash_at_height(&self, _: &Hash, _: u64) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}

#[async_trait]
impl<S: Storage> PrunedTopoheightProvider for ChainValidator<'_, S> {
    async fn get_pruned_topoheight(&self) -> Result<Option<u64>, BlockchainError> {
        let storage = self.blockchain.get_storage().read().await;
        storage.get_pruned_topoheight().await
    }

    async fn set_pruned_topoheight(&mut self, _: u64) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}

#[async_trait]
impl<S: Storage> MerkleHashProvider for ChainValidator<'_, S> {
    async fn get_balances_merkle_hash_at_topoheight(&self, topoheight: u64) -> Result<Hash, BlockchainError> {
        let storage = self.blockchain.get_storage().read().await;
        storage.get_balances_merkle_hash_at_topoheight(topoheight).await
    }

    async fn set_balances_merkle_hash_at_topoheight(&mut self,  _: u64, _: &Hash) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}