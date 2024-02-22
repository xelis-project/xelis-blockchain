use std::{
    borrow::Cow,
    collections::HashSet
};
use async_trait::async_trait;
use log::trace;
use xelis_common::{
    crypto::Hash,
    serializer::Serializer
};
use crate::core::{
    error::BlockchainError,
    storage::{
        SledStorage,
        Tips
    }
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

    // Add a block in which the transaction is included
    fn add_block_for_tx(&mut self, tx: &Hash, block: &Hash) -> Result<(), BlockchainError>;
}

#[async_trait]
impl ClientProtocolProvider for SledStorage {
    fn get_block_executor_for_tx(&self, tx: &Hash) -> Result<Hash, BlockchainError> {
        trace!("get block executer for tx {}", tx);
        self.load_from_disk(&self.txs_executed, tx.as_bytes())
    }

    fn set_tx_executed_in_block(&mut self, tx: &Hash, block: &Hash) -> Result<(), BlockchainError> {
        trace!("set tx {} executed in block {}", tx, block);
        self.txs_executed.insert(tx.as_bytes(), block.as_bytes())?;
        Ok(())
    }

    fn remove_tx_executed(&mut self, tx: &Hash) -> Result<(), BlockchainError> {
        trace!("remove tx {} executed", tx);
        self.txs_executed.remove(tx.as_bytes())?;
        Ok(())
    }

    fn is_tx_executed_in_a_block(&self, tx: &Hash) -> Result<bool, BlockchainError> {
        trace!("is tx {} executed in a block", tx);
        Ok(self.txs_executed.contains_key(tx.as_bytes())?)
    }

    fn is_tx_executed_in_block(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        trace!("is tx {} executed in block {}", tx, block);
        if let Ok(hash) = self.get_block_executor_for_tx(tx) {
            if hash == *block {
                return Ok(true)
            }
        }
        Ok(false)
    }

    fn has_tx_blocks(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has tx blocks {}", hash);
        let contains = self.tx_blocks.contains_key(hash.as_bytes())?;
        Ok(contains)
    }

    fn has_block_linked_to_tx(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        trace!("has block {} linked to tx {}", block, tx);
        Ok(self.has_tx_blocks(tx)? && self.get_blocks_for_tx(tx)?.contains(block))
    }

    fn add_block_linked_to_tx_if_not_present(&mut self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        trace!("add block {} linked to tx {} if not present", block, tx);
        let mut hashes: HashSet<Cow<'_, Hash>> = if self.has_tx_blocks(tx)? {
            self.load_from_disk(&self.tx_blocks, tx.as_bytes())?
        } else {
            HashSet::new()
        };

        let insert = hashes.insert(Cow::Borrowed(block));
        if insert {
            self.tx_blocks.insert(tx.as_bytes(), hashes.to_bytes())?;
        }

        Ok(insert)
    }

    fn get_blocks_for_tx(&self, hash: &Hash) -> Result<Tips, BlockchainError> {
        trace!("get blocks for tx {}", hash);
        self.load_from_disk(&self.tx_blocks, hash.as_bytes())
    }

    fn add_block_for_tx(&mut self, tx: &Hash, block: &Hash) -> Result<(), BlockchainError> {
        trace!("add block {} for tx {}", block, tx);
        let mut blocks = if self.has_tx_blocks(tx)? {
            self.get_blocks_for_tx(tx)?
        } else {
            Tips::new()
        };

        if !blocks.contains(&block) {
            blocks.insert(block.clone());
            self.set_blocks_for_tx(tx, &blocks)?;
        }

        Ok(())
    }

    fn set_blocks_for_tx(&mut self, tx: &Hash, blocks: &Tips) -> Result<(), BlockchainError> {
        trace!("set blocks ({}) for tx {} ", blocks.len(), tx);
        self.tx_blocks.insert(tx.as_bytes(), blocks.to_bytes())?;
        Ok(())
    }
}