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
        Ok(if let Some(snapshot) = self.snapshot.as_ref() {
            snapshot.cache.tips_cache.clone()
        } else {
            self.cache.tips_cache.clone()
        })
    }

    fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError> {
        trace!("Saving {} Tips", tips.len());
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, TIPS, tips.to_bytes())?;
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.cache.tips_cache = tips.clone();
        } else {
            self.cache.tips_cache = tips.clone();
        }
        Ok(())
    }
}