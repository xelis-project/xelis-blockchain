use async_trait::async_trait;
use crate::core::{
    error::BlockchainError,
    storage::{SnapshotProvider, snapshot::Snapshot},
};
use super::super::MemoryStorage;

#[async_trait]
impl SnapshotProvider for MemoryStorage {
    type Column = ();

    async fn has_snapshot(&self) -> Result<bool, BlockchainError> {
        Ok(false)
    }

    async fn start_snapshot(&mut self) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    async fn end_snapshot(&mut self, _: bool) -> Result<(), BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }

    fn swap_snapshot(&mut self, _: Option<Snapshot<()>>) -> Result<Option<Snapshot<()>>, BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}
