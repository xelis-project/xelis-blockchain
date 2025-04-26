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

    // Swap the position of two blocks in the execution order
    async fn swap_blocks_executions_positions(&mut self, left: &Hash, right: &Hash) -> Result<(), BlockchainError>;
}

#[async_trait]
impl BlockExecutionOrderProvider for SledStorage {
    async fn get_blocks_execution_order(&self, skip: usize, count: usize) -> Result<IndexSet<Hash>, BlockchainError> {
        let order = Self::iter_keys(self.snapshot.as_ref(), &self.blocks_execution_order)
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
        let contains = self.contains_data(&self.blocks_execution_order, hash.as_bytes())?;
        Ok(contains)
    }

    async fn add_block_execution_to_order(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        let position = if let Some(snapshot) = self.snapshot.as_mut() {
            let pos = snapshot.cache.blocks_execution_count;
            snapshot.cache.blocks_execution_count += 1;
            pos
        } else {
            let pos = self.cache.blocks_execution_count;
            self.cache.blocks_execution_count += 1;
            pos
        };

        Self::insert_into_disk(self.snapshot.as_mut(), &self.blocks_execution_order, hash.as_bytes(), &position.to_be_bytes())?;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, BLOCKS_EXECUTION_ORDER_COUNT, &position.to_be_bytes())?;

        Ok(())
    }

    async fn get_blocks_execution_count(&self) -> u64 {
        if let Some(snapshot) = self.snapshot.as_ref() {
            snapshot.cache.blocks_execution_count
        } else {
            self.cache.blocks_execution_count
        }
    }

    async fn swap_blocks_executions_positions(&mut self, left: &Hash, right: &Hash) -> Result<(), BlockchainError> {
        let left_position = self.get_block_position_in_order(left).await?;
        let right_position = self.get_block_position_in_order(right).await?;

        Self::insert_into_disk(self.snapshot.as_mut(), &self.blocks_execution_order, left.as_bytes(), &right_position.to_be_bytes())?;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.blocks_execution_order, right.as_bytes(), &left_position.to_be_bytes())?;

        Ok(())
    }
}