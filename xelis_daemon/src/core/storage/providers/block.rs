use std::sync::{atomic::Ordering, Arc};

use async_trait::async_trait;
use log::{debug, trace};
use xelis_common::{
    block::{Block, BlockHeader},
    crypto::Hash,
    difficulty::Difficulty,
    immutable::Immutable,
    serializer::Serializer,
    transaction::Transaction,
    varuint::VarUint
};
use crate::core::{error::BlockchainError, storage::{sled::BLOCKS_COUNT, SledStorage}};
use super::{BlocksAtHeightProvider, DifficultyProvider, TransactionProvider};

#[async_trait]
pub trait BlockProvider: TransactionProvider + DifficultyProvider + BlocksAtHeightProvider {
    // Check if the storage has blocks
    async fn has_blocks(&self) -> bool;

    // Count the number of blocks stored
    async fn count_blocks(&self) -> Result<u64, BlockchainError>;

    // Check if the block exists using its hash
    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Get a block with transactions using its hash
    async fn get_block_by_hash(&self, hash: &Hash) -> Result<Block, BlockchainError>;

    // Save a new block with its transactions and difficulty
    async fn save_block(&mut self, block: Arc<BlockHeader>, txs: &Vec<Immutable<Transaction>>, difficulty: Difficulty, p: VarUint, hash: Hash) -> Result<(), BlockchainError>;
}

impl SledStorage {
    // Update the blocks count and store it on disk
    fn store_blocks_count(&self, count: u64) -> Result<(), BlockchainError> {
        self.blocks_count.store(count, Ordering::SeqCst);
        self.extra.insert(BLOCKS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }
}

#[async_trait]
impl BlockProvider for SledStorage {
    async fn has_blocks(&self) -> bool {
        trace!("has blocks");
        !self.blocks.is_empty()
    }

    async fn count_blocks(&self) -> Result<u64, BlockchainError> {
        trace!("count blocks");
        Ok(self.blocks_count.load(Ordering::SeqCst))
    }

    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has block {}", hash);
        self.contains_data(&self.blocks, &self.blocks_cache, hash).await
    }

    async fn save_block(&mut self, block: Arc<BlockHeader>, txs: &Vec<Immutable<Transaction>>, difficulty: Difficulty, p: VarUint, hash: Hash) -> Result<(), BlockchainError> {
        debug!("Storing new {} with hash: {}, difficulty: {}", block, hash, difficulty);

        // Store transactions
        let mut txs_count = 0;
        for (hash, tx) in block.get_transactions().iter().zip(txs) { // first save all txs, then save block
            if !self.has_transaction(hash).await? {
                self.transactions.insert(hash.as_bytes(), tx.to_bytes())?;
                txs_count += 1;
            }
        }

        // Increase only if necessary
        if txs_count > 0 {
            self.store_transactions_count(self.count_transactions().await? + txs_count)?;
        }

        // Store block header and increase blocks count if it's a new block
        if self.blocks.insert(hash.as_bytes(), block.to_bytes())?.is_none() {
            self.store_blocks_count(self.count_blocks().await? + 1)?;
        }

        // Store difficulty
        self.difficulty.insert(hash.as_bytes(), difficulty.to_bytes())?;
        // Store P
        self.difficulty_covariance.insert(hash.as_bytes(), p.to_bytes())?;

        self.add_block_hash_at_height(hash.clone(), block.get_height()).await?;

        if let Some(cache) = &self.blocks_cache {
            let mut cache = cache.lock().await;
            cache.put(hash, block);
        }

        Ok(())
    }

    async fn get_block_by_hash(&self, hash: &Hash) -> Result<Block, BlockchainError> {
        trace!("get block by hash {}", hash);
        let block = self.get_block_header_by_hash(hash).await?;
        let mut transactions = Vec::new();
        for tx in block.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let block = Block::new(Immutable::Arc(block), transactions);
        Ok(block)
    }
}