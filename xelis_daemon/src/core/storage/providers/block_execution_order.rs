use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::crypto::Hash;
use crate::core::error::BlockchainError;

// This provider tracks the order in which blocks are added in the chain.
// This is independant of the DAG order and is used for debug purposes.
#[async_trait]
pub trait BlockExecutionOrderProvider {
    // Get the blocks execution order
    async fn get_blocks_execution_order(&self, skip: usize, count: usize) -> Result<IndexSet<Hash>, BlockchainError>;

    // Get the position of a block in the execution order
    async fn get_block_position_in_order(&self, hash: &Hash) -> Result<u64, BlockchainError>;

    // Check if a block is in the execution order
    async fn has_block_position_in_order(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Add a block to the execution order
    async fn add_block_execution_to_order(&mut self, hash: &Hash) -> Result<(), BlockchainError>;

    // Get the number of blocks executed
    async fn get_blocks_execution_count(&self) -> u64;

    // Swap the position of two blocks in the execution order
    async fn swap_blocks_executions_positions(&mut self, left: &Hash, right: &Hash) -> Result<(), BlockchainError>;
}