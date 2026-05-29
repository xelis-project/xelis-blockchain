use async_trait::async_trait;
use crate::core::{
    error::BlockchainError,
    storage::{SnapshotProvider, memory::MemoryStorageState},
};
use super::super::MemoryStorage;

#[async_trait]
impl SnapshotProvider for MemoryStorage {
    type Snapshot = MemoryStorageState;

    async fn has_snapshot(&self) -> Result<bool, BlockchainError> {
        Ok(self.snapshot.is_some())
    }

    async fn start_snapshot(&mut self) -> Result<Option<Self::Snapshot>, BlockchainError> {
        let state = self.state.clone_mut();
        Ok(self.snapshot.replace(state))
    }

    async fn end_snapshot(&mut self, apply: bool) -> Result<(), BlockchainError> {
        if apply {
            self.snapshot = None;
        } else {
            self.state = self.snapshot.take()
                .ok_or(BlockchainError::Unknown)?;
        }

        Ok(())
    }

    fn swap_snapshot(&mut self, snapshot: Option<Self::Snapshot>) -> Result<Option<Self::Snapshot>, BlockchainError> {
        Ok(std::mem::replace(&mut self.snapshot, snapshot))
    }
}
