use std::sync::Arc;
use async_trait::async_trait;
use xelis_common::{
    block::{Block, BlockHeader},
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    transaction::Transaction,
    varuint::VarUint
};
use crate::core::error::BlockchainError;
use super::{BlocksAtHeightProvider, DifficultyProvider, TransactionProvider};

#[async_trait]
pub trait BlockProvider: TransactionProvider + DifficultyProvider + BlocksAtHeightProvider {
    // Check if the storage has blocks
    async fn has_blocks(&self) -> Result<bool, BlockchainError>;

    // Count the number of blocks stored
    async fn count_blocks(&self) -> Result<u64, BlockchainError>;

    // Decrease the count of blocks that is currently stored
    async fn decrease_blocks_count(&mut self, amount: u64) -> Result<(), BlockchainError>;

    // Check if the block exists using its hash
    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Get a block with transactions using its hash
    async fn get_block_by_hash(&self, hash: &Hash) -> Result<Block, BlockchainError>;

    // Get the block size with txs included
    async fn get_block_size(&self, hash: &Hash) -> Result<usize, BlockchainError>;

    // Save a new block with its transactions and difficulty
    // Hash is Immutable to be stored efficiently in caches and sharing the same object
    // with others caches (like P2p or GetWork)
    async fn save_block(&mut self, block: Arc<BlockHeader>, txs: &[Arc<Transaction>], difficulty: Difficulty, cumulative_difficulty: CumulativeDifficulty, p: VarUint, hash: Immutable<Hash>) -> Result<(), BlockchainError>;

    // Delete a block using its hash
    async fn delete_block_with_hash(&mut self, hash: &Hash) -> Result<Block, BlockchainError>;
}