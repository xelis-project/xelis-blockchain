use async_trait::async_trait;
use log::trace;
use xelis_common::serializer::Serializer;
use crate::core::{
    error::BlockchainError,
    storage::{sled::TIPS, SledStorage, Tips}
};

#[async_trait]
pub trait TipsProvider {
    // Get current chain tips
    async fn get_tips(&self) -> Result<Tips, BlockchainError>;

    // Store chain tips
    fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError>;
}

#[async_trait]
impl TipsProvider for SledStorage {
    async fn get_tips(&self) -> Result<Tips, BlockchainError> {
        trace!("get tips");
        Ok(self.tips_cache.clone())
    }

    fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError> {
        trace!("Saving {} Tips", tips.len());
        self.extra.insert(TIPS, tips.to_bytes())?;
        self.tips_cache = tips.clone();
        Ok(())
    }

}