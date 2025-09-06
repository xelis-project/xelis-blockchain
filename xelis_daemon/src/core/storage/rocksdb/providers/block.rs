use std::sync::Arc;
use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::{Block, BlockHeader},
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    transaction::Transaction,
    varuint::VarUint,
    serializer::Serializer,
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            BlockMetadata,
            Column,
        },
        sled::{BLOCKS_COUNT, TXS_COUNT},
        BlockProvider,
        BlocksAtHeightProvider,
        DifficultyProvider,
        RocksStorage,
        TransactionProvider
    }
};

#[async_trait]
impl BlockProvider for RocksStorage {
    // Check if the storage has blocks
    async fn has_blocks(&self) -> Result<bool, BlockchainError> {
        trace!("has blocks");
        self.is_empty(Column::Blocks).map(|v| !v)
    }

    // Count the number of blocks stored
    async fn count_blocks(&self) -> Result<u64, BlockchainError> {
        trace!("count blocks");
        self.load_optional_from_disk(Column::Common, BLOCKS_COUNT)
            .map(|v| v.unwrap_or(0))
    }

    async fn decrease_blocks_count(&mut self, minus: u64) -> Result<(), BlockchainError> {
        trace!("decrease blocks count by {}", minus);
        let count = self.count_blocks().await?;
        self.insert_into_disk(Column::Common, BLOCKS_COUNT, &(count.saturating_sub(minus)))
    }

    // Check if the block exists using its hash
    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has block with hash");
        self.contains_data(Column::Blocks, hash)
    }

    // Get a block with transactions using its hash
    async fn get_block_by_hash(&self, hash: &Hash) -> Result<Block, BlockchainError> {
        trace!("get block by hash");
        let header = self.get_block_header_by_hash(hash).await?;
        let mut transactions = Vec::with_capacity(header.get_txs_count());
        for hash in header.get_txs_hashes() {
            let transaction = self.get_transaction(hash).await?;
            transactions.push(transaction.into_arc());
        }

        Ok(Block::new(header.into_arc(), transactions))
    }

    async fn get_block_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        trace!("get block size");
        let header = self.get_block_header_by_hash(hash).await?;
        let mut size = header.size();
        for hash in header.get_txs_hashes() {
            size += self.get_transaction_size(hash).await?;
        }

        Ok(size)
    }

    async fn get_block_size_ema(&self, hash: &Hash) -> Result<u32, BlockchainError> {
        self.load_block_metadata(hash).map(|m| m.size_ema)
    }

    // Save a new block with its transactions and difficulty
    // Hash is Immutable to be stored efficiently in caches and sharing the same object
    // with others caches (like P2p or GetWork)
    async fn save_block(&mut self, block: Arc<BlockHeader>, txs: &[Arc<Transaction>], difficulty: Difficulty, cumulative_difficulty: CumulativeDifficulty, covariance: VarUint, size_ema: u32, hash: Immutable<Hash>) -> Result<(), BlockchainError> {
        trace!("save block");

        let mut count_txs = 0;
        for (hash, transaction) in block.get_transactions().iter().zip(txs.iter()) {
            if !self.has_transaction(hash).await? {
                self.add_transaction(hash, &transaction).await?;
                count_txs += 1;
            }
        }

        self.insert_into_disk(Column::Blocks, hash.as_bytes(), &block)?;

        let block_difficulty = BlockMetadata {
            covariance,
            difficulty,
            cumulative_difficulty,
            size_ema
        };
        self.insert_into_disk(Column::BlockMetadata, hash.as_bytes(), &block_difficulty)?;

        self.add_block_hash_at_height(&hash, block.get_height()).await?;

        if count_txs > 0 {
            count_txs += self.count_transactions().await?;
            self.insert_into_disk(Column::Common, TXS_COUNT, &count_txs)?;
        }

        let blocks_count = self.count_blocks().await?;
        self.insert_into_disk(Column::Common, BLOCKS_COUNT, &(blocks_count + 1))
    }

    // Delete a block using its hash
    async fn delete_block_with_hash(&mut self, hash: &Hash) -> Result<Block, BlockchainError> {
        trace!("delete block with hash");
        let block = self.get_block_by_hash(hash).await?;
        self.remove_from_disk(Column::Blocks, hash)?;

        Ok(block)
    }
}

impl RocksStorage {
    pub fn load_block_metadata(&self, hash: &Hash) -> Result<BlockMetadata, BlockchainError> {
        trace!("load block difficulty {}", hash);
        self.load_from_disk(Column::BlockMetadata, hash)
    }
}