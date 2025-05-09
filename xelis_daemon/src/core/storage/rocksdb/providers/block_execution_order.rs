use async_trait::async_trait;
use log::trace;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::{
        BlockExecutionOrderProvider,
        RocksStorage,
        rocksdb::Column,
        sled::BLOCKS_EXECUTION_ORDER_COUNT,
    }
};

// This provider tracks the order in which blocks are added in the chain.
// This is independant of the DAG order and is used for debug purposes.
#[async_trait]
impl BlockExecutionOrderProvider for RocksStorage {
    // Get the blocks execution order
    async fn get_blocks_execution_order<'a>(&'a self) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("get blocks execution order");
        self.iter_keys(Column::BlocksExecutionOrder)
    }

    // Get the position of a block in the execution order
    async fn get_block_position_in_order(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        trace!("get block {} position in order", hash);
        self.load_from_disk(Column::BlocksExecutionOrder, hash)
    }

    // Check if a block is in the execution order
    async fn has_block_position_in_order(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("check if block {} is in execution order", hash);
        self.contains_data(Column::BlocksExecutionOrder, hash)
    }

    // Add a block to the execution order
    async fn add_block_execution_to_order(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        trace!("add block {} to execution order", hash);
        let position = self.get_next_block_position()?;
        self.insert_into_disk(Column::BlocksExecutionOrder, hash, &position)
    }

    // Get the number of blocks executed
    async fn get_blocks_execution_count(&self) -> u64 {
        trace!("get blocks execution count");
        // TODO
        // self.load_optional_from_disk(Column::Common, BLOCKS_EXECUTION_ORDER_COUNT)?
        //     .unwrap_or(0)
        0
    }

    // Swap the position of two blocks in the execution order
    async fn swap_blocks_executions_positions(&mut self, left: &Hash, right: &Hash) -> Result<(), BlockchainError> {
        trace!("swap blocks {} and {} execution positions", left, right);
        let left_position = self.get_block_position_in_order(left).await?;
        let right_position = self.get_block_position_in_order(right).await?;

        self.insert_into_disk(Column::BlocksExecutionOrder, right, &left_position)?;
        self.insert_into_disk(Column::BlocksExecutionOrder, left, &right_position)?;

        Ok(())
    }
}

impl RocksStorage {
    fn get_next_block_position(&mut self) -> Result<u64, BlockchainError> {
        trace!("get next block position");
        let position = self.load_optional_from_disk(Column::Common, BLOCKS_EXECUTION_ORDER_COUNT)?
            .unwrap_or(0);

        trace!("next block position is {}", position);
        self.insert_into_disk(Column::Common, BLOCKS_EXECUTION_ORDER_COUNT, &(position + 1))?;
        Ok(position)
    }
}