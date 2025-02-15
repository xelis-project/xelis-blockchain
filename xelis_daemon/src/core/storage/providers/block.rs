use std::sync::Arc;
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

    // Delete a block using its hash
    async fn delete_block_with_hash(&mut self, hash: &Hash) -> Result<Block, BlockchainError>;
}

impl SledStorage {
    // Update the blocks count and store it on disk
    fn store_blocks_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.blocks_count = count;
        } else {
            self.blocks_count = count;
        }
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, BLOCKS_COUNT, &count.to_be_bytes())?;
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
        let count = if let Some(snapshot) = &self.snapshot {
            snapshot.blocks_count
        } else {
            self.blocks_count
        };
        Ok(count)
    }

    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has block {}", hash);
        self.contains_data_cached(&self.blocks, &self.blocks_cache, hash).await
    }

    async fn save_block(&mut self, block: Arc<BlockHeader>, txs: &Vec<Immutable<Transaction>>, difficulty: Difficulty, p: VarUint, hash: Hash) -> Result<(), BlockchainError> {
        debug!("Storing new {} with hash: {}, difficulty: {}", block, hash, difficulty);

        // Store transactions
        let mut txs_count = 0;
        for (hash, tx) in block.get_transactions().iter().zip(txs) { // first save all txs, then save block
            if !self.has_transaction(hash).await? {
                Self::insert_into_disk(self.snapshot.as_mut(), &self.transactions, hash, tx.to_bytes())?;

                txs_count += 1;
            }
        }

        // Increase only if necessary
        if txs_count > 0 {
            self.store_transactions_count(self.count_transactions().await? + txs_count)?;
        }

        // Store block header and increase blocks count if it's a new block
        let no_prev = Self::insert_into_disk(self.snapshot.as_mut(), &self.blocks, hash.as_bytes(), block.to_bytes())?.is_none();
        if no_prev {
            self.store_blocks_count(self.count_blocks().await? + 1)?;
        }

        // Store difficulty
        Self::insert_into_disk(self.snapshot.as_mut(), &self.difficulty, hash.as_bytes(), difficulty.to_bytes())?;

        // Store P
        Self::insert_into_disk(self.snapshot.as_mut(), &self.difficulty_covariance, hash.as_bytes(), p.to_bytes())?;

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

    async fn delete_block_with_hash(&mut self, hash: &Hash) -> Result<Block, BlockchainError> {
        debug!("Deleting block with hash: {}", hash);

        // Delete block header
        let header = Self::delete_arc_cacheable_data(self.snapshot.as_mut(), &self.blocks, self.blocks_cache.as_mut(), &hash).await?;

        // Decrease blocks count
        self.store_blocks_count(self.count_blocks().await? - 1)?;

        // Delete difficulty
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.difficulty, hash.as_bytes())?;

        // Delete P
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.difficulty_covariance, hash.as_bytes())?;

        self.remove_block_hash_at_height(&hash, header.get_height()).await?;

        let mut transactions = Vec::new();
        for tx in header.get_transactions() {
            let transaction = self.get_transaction(&tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let block = Block::new(Immutable::Arc(header), transactions);

        Ok(block)
    }
}