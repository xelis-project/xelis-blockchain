use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::crypto::Hash;
use crate::core::{error::BlockchainError, storage::{BlockExecutionOrderProvider, Column, RocksStorage, BLOCKS_EXECUTION_ORDER_COUNT}};

// This provider tracks the order in which blocks are added in the chain.
// This is independant of the DAG order and is used for debug purposes.
#[async_trait]
impl BlockExecutionOrderProvider for RocksStorage {
    // Get the blocks execution order
    async fn get_blocks_execution_order(&self, skip: usize, count: usize) -> Result<IndexSet<Hash>, BlockchainError> {
        self.iter_keys(Column::BlocksExecutionOrder)?
            .skip(skip)
            .take(count)
            .collect::<Result<IndexSet<_>, _>>()
    }

    // Get the position of a block in the execution order
    async fn get_block_position_in_order(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        self.load_from_disk(Column::BlocksExecutionOrder, hash)
    }

    // Check if a block is in the execution order
    async fn has_block_position_in_order(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.contains_data(Column::BlocksExecutionOrder, hash)
    }

    // Add a block to the execution order
    async fn add_block_execution_to_order(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        let position = self.get_next_block_position()?;
        self.insert_into_disk(Column::BlocksExecutionOrder, hash, &position)
    }

    // Get the number of blocks executed
    async fn get_blocks_execution_count(&self) -> u64 {
        // TODO
        0
    }

    // Swap the position of two blocks in the execution order
    async fn swap_blocks_executions_positions(&mut self, left: &Hash, right: &Hash) -> Result<(), BlockchainError> {
        let left_position = self.get_block_position_in_order(left).await?;
        let right_position = self.get_block_position_in_order(right).await?;

        self.insert_into_disk(Column::BlocksExecutionOrder, right, &left_position)?;
        self.insert_into_disk(Column::BlocksExecutionOrder, left, &right_position)?;

        Ok(())
    }
}

impl RocksStorage {
    fn get_next_block_position(&mut self) -> Result<u64, BlockchainError> {
        let position = self.load_from_disk(Column::Common, BLOCKS_EXECUTION_ORDER_COUNT)?;
        self.insert_into_disk(Column::Common, BLOCKS_EXECUTION_ORDER_COUNT, &(position + 1))?;
        Ok(position)
    }
}