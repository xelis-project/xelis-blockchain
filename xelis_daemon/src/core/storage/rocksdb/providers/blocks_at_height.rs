use std::borrow::Cow;

use async_trait::async_trait;
use indexmap::IndexSet;
use log::trace;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        BlocksAtHeightProvider,
        RocksStorage
    }
};

#[async_trait]
impl BlocksAtHeightProvider for RocksStorage {
    // Check if there are blocks at a specific height
    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError> {
        trace!("has blocks at height {}", height);
        self.contains_data(Column::BlocksAtHeight, &height.to_be_bytes())
    }

    // Retrieve the blocks hashes at a specific height
    async fn get_blocks_at_height(&self, height: u64) -> Result<IndexSet<Hash>, BlockchainError> {
        trace!("get blocks at height {}", height);
        self.load_from_disk(Column::BlocksAtHeight, &height.to_be_bytes())
    }

    // This is used to store the blocks hashes at a specific height
    async fn set_blocks_at_height(&mut self, tips: &IndexSet<Hash>, height: u64) -> Result<(), BlockchainError> {
        trace!("set blocks at height {}", height);
        self.insert_into_disk(Column::BlocksAtHeight, height.to_be_bytes(), tips)
    }

    // Append a block hash at a specific height
    async fn add_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError> {
        trace!("add block hash at height {}", height);
        let mut blocks: IndexSet<Cow<'_, Hash>> = self.load_optional_from_disk(Column::BlocksAtHeight, &height.to_be_bytes())?
            .unwrap_or_default();

        if blocks.insert(Cow::Borrowed(hash)) {
            trace!("inserted block hash at height {}", height);
            self.insert_into_disk(Column::BlocksAtHeight, height.to_be_bytes(), &blocks)?;
        }

        Ok(())
    }

    // Remove a block hash at a specific height
    async fn remove_block_hash_at_height(&mut self, hash: &Hash, height: u64) -> Result<(), BlockchainError> {
        trace!("remove block hash at height {}", height);
        let Some(mut blocks): Option<IndexSet<Cow<'_, Hash>>> = self.load_optional_from_disk(Column::BlocksAtHeight, &height.to_be_bytes())? else {
            return Ok(())
        };

        if blocks.shift_remove(&Cow::Borrowed(hash)) {
            trace!("removed block hash at height {}", height);
            self.insert_into_disk(Column::BlocksAtHeight, hash, &blocks)?;
        }

        Ok(())
    }
}