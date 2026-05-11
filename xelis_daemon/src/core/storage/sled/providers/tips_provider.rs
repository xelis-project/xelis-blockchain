use async_trait::async_trait;
use log::trace;
use xelis_common::serializer::Serializer;
use crate::core::{
    error::BlockchainError,
    storage::{sled::TIPS, SledStorage, Tips, TipsProvider}
};

#[async_trait]
impl TipsProvider for SledStorage {
    async fn get_tips(&self) -> Result<Tips, BlockchainError> {
        trace!("get tips");
        self.load_optional_from_disk(&self.extra, TIPS)
            .map(|v| v.unwrap_or_default())
    }

    async fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError> {
        trace!("Saving {} Tips", tips.len());
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, TIPS, tips.to_bytes())?;

        Ok(())
    }
}