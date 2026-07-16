use anyhow::Context;
use pooled_arc::PooledArc;
use async_trait::async_trait;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::{ClientProtocolProvider, Tips},
};
use super::super::MemoryStorage;

#[async_trait]
impl ClientProtocolProvider for MemoryStorage {
    async fn get_block_executor_for_tx(&self, tx: &Hash) -> Result<Option<Hash>, BlockchainError> {
        Ok(self.transactions.get(tx)
            .and_then(|entry| entry.executed_in_block.as_ref())
            .map(|h| h.as_ref().clone()))
    }

    async fn is_tx_executed_in_a_block(&self, tx: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.transactions.get(tx).map_or(false, |entry| entry.executed_in_block.is_some()))
    }

    async fn is_tx_linked_to_blocks(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.transactions.get(hash).map_or(false, |entry| !entry.linked_blocks.is_empty()))
    }

    async fn has_block_linked_to_tx(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.transactions.get(tx).map_or(false, |entry| entry.linked_blocks.contains(block)))
    }

    async fn add_block_linked_to_tx_if_not_present(&mut self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        if let Some(entry) = self.transactions.get_mut(tx) {
            Ok(entry.linked_blocks.insert(PooledArc::from_ref(block)))
        } else {
            Err(BlockchainError::TransactionNotFound)
        }
    }

    async fn unlink_transaction_from_block(&mut self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        if let Some(entry) = self.transactions.get_mut(tx) {
            return Ok(entry.linked_blocks.remove(block));
        }
        Ok(false)
    }

    async fn get_blocks_for_tx(&self, hash: &Hash) -> Result<Tips, BlockchainError> {
        self.transactions.get(hash)
            .map(|entry| entry.linked_blocks.iter().map(|h| h.as_ref().clone()).collect())
            .with_context(|| format!("Linked blocks not found for transaction {}", hash))
            .map_err(|e| e.into())
    }

    async fn mark_tx_as_executed_in_block(&mut self, tx: &Hash, block: &Hash) -> Result<(), BlockchainError> {
        match self.transactions.get_mut(tx) {
            Some(entry) => {
                entry.executed_in_block = Some(PooledArc::from_ref(block));
                Ok(())
            },
            None => Err(BlockchainError::TransactionNotFound),
        }
    }

    async fn unmark_tx_from_executed(&mut self, tx: &Hash) -> Result<(), BlockchainError> {
        if let Some(entry) = self.transactions.get_mut(tx) {
            entry.executed_in_block = None;
            Ok(())
        } else {
            Err(BlockchainError::TransactionNotFound)
        }
    }

    async fn set_blocks_for_tx(&mut self, tx: &Hash, blocks: &Tips) -> Result<(), BlockchainError> {
        if let Some(entry) = self.transactions.get_mut(tx) {
            entry.linked_blocks = blocks.iter().map(|h| PooledArc::from_ref(h)).collect();
            Ok(())
        } else {
            Err(BlockchainError::TransactionNotFound)
        }
    }
}
