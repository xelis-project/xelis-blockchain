use async_trait::async_trait;
use crate::core::{
    error::BlockchainError,
    storage::{TipsProvider, Tips},
};
use super::super::MemoryStorage;

#[async_trait]
impl TipsProvider for MemoryStorage {
    async fn get_tips(&self) -> Result<Tips, BlockchainError> {
        Ok(self.tips.clone())
    }

    async fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError> {
        self.tips = tips.clone();
        Ok(())
    }
}
