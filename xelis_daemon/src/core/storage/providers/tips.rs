use async_trait::async_trait;
use crate::core::{error::BlockchainError, storage::Tips};

#[async_trait]
pub trait TipsProvider {
    // Get current chain tips
    async fn get_tips(&self) -> Result<Tips, BlockchainError>;

    // Store chain tips
    async fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError>;
}