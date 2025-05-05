use async_trait::async_trait;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::Tips
};

#[async_trait]
pub trait ClientProtocolProvider {
    // Get the block hash that executed the transaction
    fn get_block_executor_for_tx(&self, tx: &Hash) -> Result<Hash, BlockchainError>;

    // Check if the transaction was executed
    fn is_tx_executed_in_a_block(&self, tx: &Hash) -> Result<bool, BlockchainError>;

    // Check if the transaction was executed in a specific block
    fn is_tx_executed_in_block(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError>;

    // Is the transaction included in at least a block
    fn has_tx_blocks(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Is the block linked to the transaction
    fn has_block_linked_to_tx(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError>;

    // Same as has_block_linked_to_tx + add_block_for_tx but read only one time
    fn add_block_linked_to_tx_if_not_present(&mut self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError>;

    // Get all blocks in which the transaction is included
    fn get_blocks_for_tx(&self, hash: &Hash) -> Result<Tips, BlockchainError>;

    // Set the block hash that executed the transaction
    fn set_tx_executed_in_block(&mut self, tx: &Hash, block: &Hash) -> Result<(), BlockchainError>;

    // Unmark the transaction as executed
    fn remove_tx_executed(&mut self, tx: &Hash) -> Result<(), BlockchainError>;

    // Set all blocks in which the transaction is included
    fn set_blocks_for_tx(&mut self, tx: &Hash, blocks: &Tips) -> Result<(), BlockchainError>;
}