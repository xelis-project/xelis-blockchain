use std::sync::atomic::Ordering;

use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{crypto::Hash, serializer::Serializer};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{sled::BLOCKS_EXECUTION_ORDER_COUNT, SledStorage}
};

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
}

impl SledStorage {

}

#[async_trait]
impl BlockExecutionOrderProvider for SledStorage {
    async fn get_blocks_execution_order(&self, skip: usize, count: usize) -> Result<IndexSet<Hash>, BlockchainError> {
        let order = self.blocks_execution_order.iter()
            .keys()
            .skip(skip)
            .take(count)
            .map(|x| Ok(Hash::from_bytes(&x?)?))
            .collect::<Result<_, BlockchainError>>()?;

        Ok(order)
    }

    async fn get_block_position_in_order(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        let position = self.load_from_disk(&self.blocks_execution_order, hash.as_bytes(), DiskContext::SearchBlockPositionInOrder)?;
        Ok(position)
    }

    async fn has_block_position_in_order(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        let position = self.blocks_execution_order.contains_key(hash.as_bytes())?;
        Ok(position)
    }

    async fn add_block_execution_to_order(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        let position = self.blocks_execution_count.fetch_add(1, Ordering::SeqCst);
        self.blocks_execution_order.insert(hash.to_bytes(), position.to_bytes())?;
        self.extra.insert(BLOCKS_EXECUTION_ORDER_COUNT, &position.to_be_bytes())?;
        Ok(())
    }

    async fn get_blocks_execution_count(&self) -> u64 {
        self.blocks_execution_count.load(Ordering::SeqCst)
    }
}