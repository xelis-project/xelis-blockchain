use anyhow::Context;
use pooled_arc::PooledArc;
use std::sync::Arc;
use async_trait::async_trait;
use xelis_common::{
    block::{Block, BlockHeader},
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    serializer::Serializer,
    transaction::Transaction,
    varuint::VarUint,
};
use crate::core::{
    error::BlockchainError,
    storage::{
        BlockProvider,
        BlocksAtHeightProvider,
        ClientProtocolProvider,
        DifficultyProvider,
        TransactionProvider,
        MergeSet,
        memory::BlockEntry,
    },
};
use super::super::{BlockMetadata, MemoryStorage};

#[async_trait]
impl BlockProvider for MemoryStorage {
    async fn has_blocks(&self) -> Result<bool, BlockchainError> {
        Ok(!self.blocks.is_empty())
    }

    async fn count_blocks(&self) -> Result<u64, BlockchainError> {
        Ok(self.blocks.len() as u64)
    }

    async fn decrease_blocks_count(&mut self, _: u64) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.blocks.contains_key(hash))
    }

    async fn get_block_by_hash(&self, hash: &Hash) -> Result<Block, BlockchainError> {
        let entry = self.blocks.get(hash)
            .with_context(|| format!("Block not found for hash {}", hash))?;

        let header = &entry.header;
        let mut transactions = Vec::with_capacity(header.get_txs_count());
        for tx_hash in header.get_txs_hashes() {
            let tx = self.get_transaction(tx_hash).await?;
            transactions.push(tx.into_arc());
        }

        Ok(Block::new(header.clone(), transactions))
    }

    async fn get_block_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        let header = self.get_block_header_by_hash(hash).await?;
        let mut size = header.size();
        for tx_hash in header.get_txs_hashes() {
            size += self.get_transaction_size(tx_hash).await?;
        }
        Ok(size)
    }

    async fn get_block_size_ema(&self, hash: &Hash) -> Result<u32, BlockchainError> {
        self.blocks.get(hash)
            .map(|entry| entry.metadata.size_ema)
            .with_context(|| format!("Block size EMA not found for hash {}", hash))
            .map_err(|e| e.into())
    }

    async fn save_block(
        &mut self,
        block: Arc<BlockHeader>,
        txs: &[Arc<Transaction>],
        mergeset: MergeSet,
        difficulty: Difficulty,
        cumulative_difficulty: CumulativeDifficulty,
        covariance: VarUint,
        size_ema: u32,
        hash: Immutable<Hash>,
    ) -> Result<(), BlockchainError> {
        for (tx_hash, transaction) in block.get_transactions().iter().zip(txs.iter()) {
            if !self.has_transaction(tx_hash).await? {
                self.add_transaction(tx_hash, transaction).await?;
            }
        }

        let height = block.get_height();
        self.blocks.insert(PooledArc::from_ref(hash.as_ref()), BlockEntry {
            header: block,
            metadata: BlockMetadata {
                difficulty,
                cumulative_difficulty,
                covariance,
                size_ema,
            },
            mergeset,
        });

        self.add_block_hash_at_height(&hash, height).await?;

        Ok(())
    }

    async fn delete_block_by_hash(&mut self, hash: &Hash) -> Result<Immutable<BlockHeader>, BlockchainError> {
        let entry = self.blocks.shift_remove(hash)
            .with_context(|| format!("Cannot delete block, not found: {}", hash))?;

        let header = entry.header;
        self.remove_block_hash_at_height(hash, header.get_height()).await?;

        for tx in header.get_transactions() {
            self.unlink_transaction_from_block(tx, hash).await?;
        }

        Ok(Immutable::Arc(header))
    }
}
