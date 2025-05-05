use std::{borrow::Cow, collections::HashSet};

use async_trait::async_trait;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::{ClientProtocolProvider, Column, RocksStorage, Tips}
};

#[async_trait]
impl ClientProtocolProvider for RocksStorage {
    // Get the block hash that executed the transaction
    fn get_block_executor_for_tx(&self, tx: &Hash) -> Result<Hash, BlockchainError> {
        self.load_from_disk(Column::TransactionsExecuted, tx)
    }

    // Check if the transaction was executed
    fn is_tx_executed_in_a_block(&self, tx: &Hash) -> Result<bool, BlockchainError> {
        self.contains_data(Column::TransactionsExecuted, tx)
    }

    // Check if the transaction was executed in a specific block
    fn is_tx_executed_in_block(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        if let Ok(hash) = self.get_block_executor_for_tx(tx) {
            return Ok(hash == *block)
        }

        Ok(false)
    }

    // Is the transaction included in at least a block
    fn has_tx_blocks(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.contains_data(Column::TransactionInBlocks, hash)
    }

    // Is the block linked to the transaction
    fn has_block_linked_to_tx(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.has_tx_blocks(tx)? && self.get_blocks_for_tx(tx)?.contains(block))
    }

    // Same as has_block_linked_to_tx + add_block_for_tx but read only one time
    fn add_block_linked_to_tx_if_not_present(&mut self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        let mut hashes: HashSet<Cow<'_, Hash>> = self.load_optional_from_disk(Column::TransactionInBlocks, tx)?
            .unwrap_or_else(HashSet::new);

        if hashes.insert(Cow::Borrowed(block)) {
            self.insert_into_disk(Column::TransactionInBlocks, tx, &hashes)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // Get all blocks in which the transaction is included
    fn get_blocks_for_tx(&self, hash: &Hash) -> Result<Tips, BlockchainError> {
        self.load_from_disk(Column::TransactionInBlocks, hash)
    }

    // Set the block hash that executed the transaction
    fn set_tx_executed_in_block(&mut self, tx: &Hash, block: &Hash) -> Result<(), BlockchainError> {
        self.insert_into_disk(Column::TransactionsExecuted, tx, block)
    }

    // Unmark the transaction as executed
    fn remove_tx_executed(&mut self, tx: &Hash) -> Result<(), BlockchainError> {
        self.remove_from_disk(Column::TransactionsExecuted, tx)
    }

    // Set all blocks in which the transaction is included
    fn set_blocks_for_tx(&mut self, tx: &Hash, blocks: &Tips) -> Result<(), BlockchainError> {
        self.insert_into_disk(Column::TransactionInBlocks, tx, blocks)
    }
}