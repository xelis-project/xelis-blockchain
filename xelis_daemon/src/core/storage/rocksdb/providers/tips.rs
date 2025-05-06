use async_trait::async_trait;

use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        sled::TIPS,
        Tips,
        RocksStorage,
        TipsProvider,
    }
};

#[async_trait]
impl TipsProvider for RocksStorage {
    // Get current chain tips
    async fn get_tips(&self) -> Result<Tips, BlockchainError> {
        self.load_from_disk(Column::Common, TIPS)
    }

    // Store chain tips
    async fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError> {
        self.insert_into_disk(Column::Common, TIPS, tips)
    }
}