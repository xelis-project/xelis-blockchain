use async_trait::async_trait;
use log::trace;

use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, TIPS},
        Tips,
        RocksStorage,
        TipsProvider,
    }
};

#[async_trait]
impl TipsProvider for RocksStorage {
    // Get current chain tips
    async fn get_tips(&self) -> Result<Tips, BlockchainError> {
        trace!("get tips");
        self.load_optional_from_disk(Column::Common, TIPS)
            .map(|v| v.unwrap_or_default())
    }

    // Store chain tips
    async fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError> {
        trace!("store tips");
        self.cache_mut().chain.tips = tips.clone();
        self.insert_into_disk(Column::Common, TIPS, tips)
    }
}