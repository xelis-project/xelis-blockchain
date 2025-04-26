use std::sync::Arc;
use async_trait::async_trait;
use indexmap::{IndexMap, IndexSet};
use xelis_common::{
    block::{TopoHeight, BlockHeader},
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
    hard_fork::{get_pow_algorithm_for_version, get_version_at_height},
    storage::{
        BlocksAtHeightProvider,
        DagOrderProvider,
        DifficultyProvider,
        MerkleHashProvider,
        PrunedTopoheightProvider,
        Storage
    }
};
use log::{debug, trace};

// This struct is used to store the block data in the chain validator
struct BlockData {
    header: Arc<BlockHeader>,
    difficulty: Difficulty,
    cumulative_difficulty: Option<CumulativeDifficulty>,
    p: VarUint
}

// Chain validator is used to validate the blocks received from the network
// We store the blocks in topological order and we verify the proof of work validity
// This is doing only minimal checks and valid chain order based on topoheight and difficulty
pub struct ChainValidator<'a, S: Storage> {
    // store all blocks data in topological order
    blocks: IndexMap<Hash, BlockData>,
    // store all blocks hashes at a specific height
    blocks_at_height: IndexMap<u64, IndexSet<Hash>>,
    // Blockchain reference used to verify current chain state
    blockchain: &'a Blockchain<S>,
    // This is used to compute the expected topoheight of each new block
    // It must be 1 topoheight above the common point
    starting_topoheight: TopoHeight,
}

// This struct is passed as the Provider param.
// It helps us to keep the lock of the storage and prevent any
// deadlock that could happen if a block is propagated at same time
struct ChainValidatorProvider<'a, S: Storage> {
    parent: &'a ChainValidator<'a, S>,
    storage: &'a S,
}

impl<'a, S: Storage> ChainValidator<'a, S> {
    // Starting topoheight must be 1 topoheight above the common point
    pub fn new(blockchain: &'a Blockchain<S>, starting_topoheight: TopoHeight) -> Self {        
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
            debug!("locking storage for cumulative difficulty");
            let storage = self.blockchain.get_storage().read().await;
            debug!("storage lock acquired for cumulative difficulty");
            let top_block_hash = self.blockchain.get_top_block_hash_for_storage(&storage).await?;
            storage.get_cumulative_difficulty_for_block_hash(&top_block_hash).await?
        };

        Ok(*new_cumulative_difficulty > current_cumulative_difficulty)
    }

    // Retrieve the cumulative difficulty of the chain validator
    // It is the cumulative difficulty of the last block added
    pub fn get_chain_cumulative_difficulty(&self) -> Option<&CumulativeDifficulty> {
        let (_, data) = self.blocks.last()?;
        data.cumulative_difficulty.as_ref()
    }

    // validate the basic chain structure
    // We expect that the block added is the next block ordered by topoheight
    pub async fn insert_block(&mut self, hash: Hash, header: BlockHeader) -> Result<(), BlockchainError> {
        debug!("Inserting block {} into chain validator", hash);

        if self.blocks.contains_key(&hash) {
            debug!("Block {} is already in validator chain!", hash);
            return Err(BlockchainError::AlreadyInChain)
        }

        let storage = self.blockchain.get_storage().read().await;
        debug!("storage locked for chain validator insert block");

        if storage.has_block_with_hash(&hash).await? {
            debug!("Block {} is already in blockchain!", hash);
            return Err(BlockchainError::AlreadyInChain)
        }

        let provider = ChainValidatorProvider {
            parent: &self,
            storage: &storage,
        };

        // Verify the block version
        let version = get_version_at_height(self.blockchain.get_network(), header.get_height());
        if version != header.get_version() {
            debug!("Block {} has version {} while expected version is {}", hash, header.get_version(), version);
            return Err(BlockchainError::InvalidBlockVersion)
        }

        // Verify the block height by tips
        let height_at_tips = blockdag::calculate_height_at_tips(&provider, header.get_tips().iter()).await?;
        if height_at_tips != header.get_height() {
            debug!("Block {} has height {} while expected height is {}", hash, header.get_height(), height_at_tips);
            return Err(BlockchainError::InvalidBlockHeight(height_at_tips, header.get_height()))
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
            let height_by_tips = blockdag::calculate_height_at_tips(&provider, header.get_tips().iter()).await?;
            if height_by_tips != header.get_height() {
                debug!("Block {} has height {} while expected height is {}", hash, header.get_height(), height_by_tips);
                return Err(BlockchainError::InvalidBlockHeight(height_by_tips, header.get_height()))
            }
        }

        let algorithm = get_pow_algorithm_for_version(version);
        let pow_hash = header.get_pow_hash(algorithm)?;
        trace!("POW hash: {}", pow_hash);
        let (difficulty, p) = self.blockchain.verify_proof_of_work(&provider, &pow_hash, tips.iter()).await?;

        // Find the common base between the block and the current blockchain
        let (base, base_height) = self.blockchain.find_common_base(&provider, header.get_tips()).await?;

        trace!("Common base: {} at height {} and hash {}", base, base_height, hash);

        // Store the block in both maps
        // One is for blocks at height and the other is for the block data
        self.blocks_at_height.entry(header.get_height()).or_insert_with(IndexSet::new).insert(hash.clone());
        self.blocks.insert(hash.clone(), BlockData { header: Arc::new(header), difficulty, cumulative_difficulty: None, p });

        // Re create the provider for the cumulative difficulty below
        let provider = ChainValidatorProvider {
            parent: &self,
            storage: &storage,
        };

        // Find the cumulative difficulty for this block
        let (_, cumulative_difficulty) = self.blockchain.find_tip_work_score(&provider, &hash, &base, base_height).await?;

        let entry = self.blocks.get_mut(&hash).ok_or_else(|| BlockchainError::Unknown)?;
        entry.cumulative_difficulty = Some(cumulative_difficulty);

        Ok(())
    }

    // Retrieve all blocks from the chain validator
    pub fn get_blocks(self) -> impl Iterator<Item = (Hash, Arc<BlockHeader>)> {
        self.blocks.into_iter().map(|(hash, data)| (hash, data.header))
    }
}

#[async_trait]
impl<S: Storage> DifficultyProvider for ChainValidatorProvider<'_, S> {
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        trace!("get height for block hash {}", hash);
        if let Some(data) = self.parent.blocks.get(hash) {
            return Ok(data.header.get_height())
        }

        trace!("fallback on storage for get_height_for_block_hash");
        self.storage.get_height_for_block_hash(hash).await
    }

    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<TimestampMillis, BlockchainError> {
        trace!("get timestamp for block hash {}", hash);
        if let Some(data) = self.parent.blocks.get(hash) {
            return Ok(data.header.get_timestamp())
        }

        trace!("fallback on storage for get_timestamp_for_block_hash");
        self.storage.get_timestamp_for_block_hash(hash).await
    }

    async fn get_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError> {
        trace!("get difficulty for block hash {}", hash);
        if let Some(data) = self.parent.blocks.get(hash) {
            return Ok(data.difficulty)
        }

        trace!("fallback on storage for get_difficulty_for_block_hash");
        self.storage.get_difficulty_for_block_hash(hash).await
    }

    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<CumulativeDifficulty, BlockchainError> {
        trace!("get cumulative difficulty for block hash {}", hash);
        if let Some(data) = self.parent.blocks.get(hash) {
            if let Some(cumulative_difficulty) = data.cumulative_difficulty {
                return Ok(cumulative_difficulty)
            }
        }

        trace!("fallback on storage for get_cumulative_difficulty_for_block_hash");
        self.storage.get_cumulative_difficulty_for_block_hash(hash).await
    }

    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Immutable<IndexSet<Hash>>, BlockchainError> {
        trace!("get past blocks for block hash {}", hash);
        if let Some(data) = self.parent.blocks.get(hash) {
            return Ok(Immutable::Owned(data.header.get_tips().clone()))
        }

        trace!("fallback on storage for get_past_blocks_for_block_hash");
        self.storage.get_past_blocks_for_block_hash(hash).await
    }

    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        trace!("get block header by hash {}", hash);
        if let Some(data) = self.parent.blocks.get(hash) {
            return Ok(data.header.clone())
        }

        trace!("fallback on storage for get_block_header_by_hash");
        self.storage.get_block_header_by_hash(hash).await
    }

    async fn get_estimated_covariance_for_block_hash(&self, hash: &Hash) -> Result<VarUint, BlockchainError> {
        trace!("get estimated covariance for block hash {}", hash);
        if let Some(data) = self.parent.blocks.get(hash) {
            return Ok(data.p.clone())
        }

        trace!("fallback on storage for get_estimated_covariance_for_block_hash");
        self.storage.get_estimated_covariance_for_block_hash(hash).await
    }

    async fn set_estimated_covariance_for_block_hash(&mut self, _: &Hash, _: VarUint) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    async fn set_cumulative_difficulty_for_block_hash(&mut self, _: &Hash, _: CumulativeDifficulty) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}

#[async_trait]
impl<S: Storage> DagOrderProvider for ChainValidatorProvider<'_, S> {
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        trace!("get topo height for hash {}", hash);
        if let Some(index) = self.parent.blocks.get_index_of(hash) {
            return Ok(self.parent.starting_topoheight + index as TopoHeight)
        }

        trace!("fallback on storage for get_topo_height_for_hash");
        self.storage.get_topo_height_for_hash(hash).await
    }

    // This should never happen in our case
    async fn set_topo_height_for_block(&mut self, _: &Hash, _: TopoHeight) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    async fn is_block_topological_ordered(&self, hash: &Hash) -> bool {
        trace!("is block topological ordered {}", hash);
        if self.parent.blocks.contains_key(hash) {
            return true
        }

        trace!("fallback on storage for is_block_topological_ordered");
        self.storage.is_block_topological_ordered(hash).await
    }

    async fn get_hash_at_topo_height(&self, topoheight: TopoHeight) -> Result<Hash, BlockchainError> {
        trace!("get hash at topoheight {}", topoheight);
        if topoheight >= self.parent.starting_topoheight {
            let index = (topoheight - self.parent.starting_topoheight) as usize;
            return self.parent.blocks.get_index(index).map(|(hash, _)| hash.clone()).ok_or(BlockchainError::BlockNotOrdered);
        }

        trace!("fallback on storage for get_hash_at_topo_height");
        self.storage.get_hash_at_topo_height(topoheight).await
    }

    async fn has_hash_at_topoheight(&self, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has hash at topoheight {}", topoheight);
        if topoheight >= self.parent.starting_topoheight {
            let index = (topoheight - self.parent.starting_topoheight) as usize;
            return Ok(self.parent.blocks.get_index(index).is_some())
        }

        trace!("fallback on storage for has_hash_at_topoheight");
        self.storage.has_hash_at_topoheight(topoheight).await
    }
}

#[async_trait]
impl<S: Storage> BlocksAtHeightProvider for ChainValidatorProvider<'_, S> {
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError> {
        trace!("has block at height {}", height);
        if self.parent.blocks_at_height.contains_key(&height) {
            return Ok(true)
        }

        trace!("fallback on storage for has_blocks_at_height");
        self.storage.has_blocks_at_height(height).await
    }

    // Retrieve the blocks hashes at a specific height
    async fn get_blocks_at_height(&self, height: u64) -> Result<IndexSet<Hash>, BlockchainError> {
        trace!("get blocks at height {}", height);
        if let Some(tips) = self.parent.blocks_at_height.get(&height) {
            return Ok(tips.clone())
        }

        trace!("fallback on storage for get_blocks_at_height");
        self.storage.get_blocks_at_height(height).await
    }

    // This is used to store the blocks hashes at a specific height
    async fn set_blocks_at_height(&mut self, _: IndexSet<Hash>, _: u64) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    // Append a block hash at a specific height
    async fn add_block_hash_at_height(&mut self, _: Hash, _: u64) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    // Remove a block hash at a specific height
    async fn remove_block_hash_at_height(&mut self, _: &Hash, _: u64) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}

#[async_trait]
impl<S: Storage> PrunedTopoheightProvider for ChainValidatorProvider<'_, S> {
    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("fallback on storage for get_pruned_topoheight");
        self.storage.get_pruned_topoheight().await
    }

    async fn set_pruned_topoheight(&mut self, _: TopoHeight) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}

#[async_trait]
impl<S: Storage> MerkleHashProvider for ChainValidatorProvider<'_, S> {
    async fn get_balances_merkle_hash_at_topoheight(&self, topoheight: TopoHeight) -> Result<Hash, BlockchainError> {
        trace!("fallback on storage for get_balances_merkle_hash_at_topoheight");
        self.storage.get_balances_merkle_hash_at_topoheight(topoheight).await
    }

    async fn set_balances_merkle_hash_at_topoheight(&mut self,  _: TopoHeight, _: &Hash) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}