use std::sync::Arc;
use async_trait::async_trait;
use log::{debug, trace};
use xelis_common::{
    block::{Block, BlockHeader},
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    serializer::Serializer,
    transaction::Transaction,
    varuint::VarUint
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        sled::BLOCKS_COUNT,
        BlockProvider,
        BlocksAtHeightProvider,
        ClientProtocolProvider,
        DifficultyProvider,
        TransactionProvider,
        SledStorage,
    }
};

impl SledStorage {
    // Update the blocks count and store it on disk
    fn store_blocks_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        self.cache_mut().blocks_count = count;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, BLOCKS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }
}

#[async_trait]
impl BlockProvider for SledStorage {
    async fn has_blocks(&self) -> Result<bool, BlockchainError> {
        trace!("has blocks");
        Ok(!self.blocks.is_empty())
    }

    async fn count_blocks(&self) -> Result<u64, BlockchainError> {
        trace!("count blocks");
        Ok(self.cache().blocks_count)
    }

    async fn decrease_blocks_count(&mut self, amount: u64) -> Result<(), BlockchainError> {
        trace!("count blocks");
        self.store_blocks_count(self.count_blocks().await? - amount)?;

        Ok(())
    }

    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has block {}", hash);
        self.contains_data_cached(&self.blocks, self.cache.objects.as_ref().map(|o| &o.blocks_cache), hash).await
    }

    async fn get_block_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        trace!("get block size {}", hash);
        let header = self.get_block_header_by_hash(hash).await?;
        let mut size = header.size();
        for hash in header.get_txs_hashes() {
            size += self.get_transaction_size(hash).await?;
        }

        Ok(size)
    }

    async fn get_block_size_ema(&self, hash: &Hash) -> Result<u32, BlockchainError> {
        trace!("get block size ema {}", hash);
        self.load_from_disk(&self.block_size_ema, hash.as_bytes(), DiskContext::BlockSizeEma)
    }

    async fn save_block(&mut self, block: Arc<BlockHeader>, txs: &[Arc<Transaction>], difficulty: Difficulty, cumulative_difficulty: CumulativeDifficulty, p: VarUint, size_ema: u32, hash: Immutable<Hash>) -> Result<(), BlockchainError> {
        debug!("Storing new {} with hash: {}, difficulty: {}, snapshot mode: {}", block, hash, difficulty, self.snapshot.is_some());

        // Store transactions
        let mut txs_count = 0;
        for (hash, tx) in block.get_transactions().iter().zip(txs) { // first save all txs, then save block
            if !self.has_transaction(hash).await? {
                self.add_transaction(hash, &tx).await?;
                txs_count += 1;
            }
        }

        // Increase only if necessary
        if txs_count > 0 {
            self.store_transactions_count(self.count_transactions().await? + txs_count)?;
        }

        if !self.has_block_with_hash(&hash).await? {
            self.store_blocks_count(self.count_blocks().await? + 1)?;
        }

        // Store block header and increase blocks count if it's a new block
        Self::insert_into_disk(self.snapshot.as_mut(), &self.blocks, hash.as_bytes(), block.to_bytes())?;

        // Store difficulty
        Self::insert_into_disk(self.snapshot.as_mut(), &self.difficulty, hash.as_bytes(), difficulty.to_bytes())?;

        // Store cumulative difficulty
        Self::insert_into_disk(self.snapshot.as_mut(), &self.cumulative_difficulty, hash.as_bytes(), cumulative_difficulty.to_bytes())?;

        // Store P
        Self::insert_into_disk(self.snapshot.as_mut(), &self.difficulty_covariance, hash.as_bytes(), p.to_bytes())?;

        // Store EMA
        Self::insert_into_disk(self.snapshot.as_mut(), &self.block_size_ema, hash.as_bytes(), size_ema.to_bytes())?;

        self.add_block_hash_at_height(&hash, block.get_height()).await?;

        if let Some(cache) = self.cache_mut().objects.as_mut().map(|o| &mut o.blocks_cache) {
            // TODO: no clone
            cache.get_mut().put(hash.into_owned(), block);
        }

        Ok(())
    }

    async fn get_block_by_hash(&self, hash: &Hash) -> Result<Block, BlockchainError> {
        trace!("get block by hash {}", hash);
        let header = self.get_block_header_by_hash(hash).await?;
        let mut transactions = Vec::with_capacity(header.get_txs_count());
        for tx in header.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(transaction.into_arc());
        }

        let block = Block::new(header.into_arc(), transactions);
        Ok(block)
    }

    async fn delete_block_by_hash(&mut self, hash: &Hash) -> Result<Immutable<BlockHeader>, BlockchainError> {
        debug!("Deleting block with hash: {}", hash);

        // Delete block header
        let header = Self::delete_arc_cacheable_data(self.snapshot.as_mut(), &self.blocks, self.cache.objects.as_mut().map(|o| &mut o.blocks_cache), &hash).await?;

        // Decrease blocks count
        self.store_blocks_count(self.count_blocks().await? - 1)?;

        // Delete difficulty
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.difficulty, hash.as_bytes())?;

        // Delete cumulative difficulty
        Self::delete_cacheable_data(self.snapshot.as_mut(), &self.cumulative_difficulty, self.cache.objects.as_mut().map(|o| &mut o.cumulative_difficulty_cache), &hash).await?;

        // Delete P
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.difficulty_covariance, hash.as_bytes())?;

        self.remove_block_hash_at_height(&hash, header.get_height()).await?;

        for tx in header.get_transactions() {
            self.unlink_transaction_from_block(tx, hash).await?;
        }

        Ok(header)
    }
}