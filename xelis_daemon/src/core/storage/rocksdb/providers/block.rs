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
use crate::core::{error::BlockchainError, storage::{BlockDifficulty, BlockProvider, Column, DifficultyProvider, RocksStorage, TransactionProvider}};

#[async_trait]
impl BlockProvider for RocksStorage {
    // Check if the storage has blocks
    async fn has_blocks(&self) -> bool {
        todo!()
    }

    // Count the number of blocks stored
    async fn count_blocks(&self) -> Result<u64, BlockchainError> {
        todo!()
    }

    // Check if the block exists using its hash
    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.contains_data(Column::Blocks, hash)
    }

    // Get a block with transactions using its hash
    async fn get_block_by_hash(&self, hash: &Hash) -> Result<Block, BlockchainError> {
        let header = self.get_block_header_by_hash(hash).await?;
        let mut transactions = Vec::with_capacity(header.get_txs_count());
        for hash in header.get_txs_hashes() {
            let transaction = self.get_transaction(hash).await?;
            transactions.push(transaction);
        }

        Ok(Block::new(header, transactions))
    }

    // Save a new block with its transactions and difficulty
    // Hash is Immutable to be stored efficiently in caches and sharing the same object
    // with others caches (like P2p or GetWork)
    async fn save_block(&mut self, block: Arc<BlockHeader>, txs: &Vec<Immutable<Transaction>>, difficulty: Difficulty, cumulative_difficulty: CumulativeDifficulty, covariance: VarUint, hash: Immutable<Hash>) -> Result<(), BlockchainError> {
        for (hash, transaction) in block.get_transactions().iter().zip(txs.iter()) {
            self.add_transaction(hash, &transaction).await?;
        }

        self.insert_into_disk(Column::Blocks, &hash, &block)?;

        let block_difficulty = BlockDifficulty {
            covariance,
            difficulty,
            cumulative_difficulty
        };
        self.insert_into_disk(Column::BlockDifficulty, &hash, &block_difficulty)?;

        Ok(())
    }

    // Delete a block using its hash
    async fn delete_block_with_hash(&mut self, hash: &Hash) -> Result<Block, BlockchainError> {
        let block = self.get_block_by_hash(hash).await?;
        self.remove_from_disk(Column::Blocks, hash)?;

        Ok(block)
    }
}