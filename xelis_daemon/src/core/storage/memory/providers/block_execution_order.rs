use async_trait::async_trait;
use anyhow::Context;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::BlockExecutionOrderProvider,
};
use super::super::MemoryStorage;

#[async_trait]
impl BlockExecutionOrderProvider for MemoryStorage {
    async fn get_blocks_execution_order<'a>(&'a self) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        Ok(self.blocks.keys()
            .map(|h| Ok(h.as_ref().clone())))
    }

    async fn get_block_position_in_order(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        self.blocks.get_index_of(hash)
            .map(|idx| idx as u64)
            .with_context(|| format!("Block position in order not found for block {}", hash))
            .map_err(|e| e.into())
    }

    async fn has_block_position_in_order(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.blocks.contains_key(hash))
    }

    async fn add_block_execution_to_order(&mut self, _: &Hash) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn get_blocks_execution_count(&self) -> Result<u64, BlockchainError> {
        Ok(self.blocks.len() as u64)
    }

    async fn swap_blocks_executions_positions(&mut self, left: &Hash, right: &Hash) -> Result<(), BlockchainError> {
        let left_pos = self.get_block_position_in_order(left).await?;
        let right_pos = self.get_block_position_in_order(right).await?;
        self.blocks.swap_indices(left_pos as usize, right_pos as usize);

        Ok(())
    }
}
