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
        Ok(self.snapshot.is_some())
    }

    async fn start_snapshot(&mut self) -> Result<Option<Snapshot<()>>, BlockchainError> {
        if self.snapshot.is_some() {
            return Err(BlockchainError::UnsupportedOperation);
        }

        let snapshot = Snapshot::new(Default::default());
        self.snapshot = Some(self.state.clone_mut());

        Ok(Some(snapshot))
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

    fn swap_snapshot(&mut self, _: Option<Snapshot<()>>) -> Result<Option<Snapshot<()>>, BlockchainError> {
        Err(BlockchainError::UnsupportedOperation)
    }
}
