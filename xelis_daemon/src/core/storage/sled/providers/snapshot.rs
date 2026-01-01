use async_trait::async_trait;
use log::trace;
use crate::core::{
    error::BlockchainError,
    storage::{
        sled::{Snapshot, TreeWrapper},
        SledStorage,
        SnapshotProvider
    }
};

#[async_trait]
impl SnapshotProvider for SledStorage {
    type Column = TreeWrapper;

    // Check if we have a commit point already set
    async fn has_snapshot(&self) -> Result<bool, BlockchainError> {
        trace!("has snapshot");
        Ok(self.snapshot.is_some())
    }

    async fn start_snapshot(&mut self) -> Result<(), BlockchainError> {
        trace!("start snapshot");
        if self.snapshot.is_some() {
            return Err(BlockchainError::CommitPointAlreadyStarted);
        }

        let snapshot = Snapshot::new(self.cache.clone_mut());
        self.snapshot = Some(snapshot);
        Ok(())
    }

    fn end_snapshot(&mut self, apply: bool) -> Result<(), BlockchainError> {
        trace!("end snapshot");
        let snapshot = self.snapshot.take()
            .ok_or(BlockchainError::CommitPointNotStarted)?;

        if apply {
            self.cache = snapshot.cache;

            for (tree, batch) in snapshot.trees {
                trace!("Applying batch to tree {:?}", tree.0.name());
                for (key, value) in batch.into_iter() {
                    match value {
                        Some(value) => tree.insert(key, value.as_ref())?,
                        None => tree.remove(key)?,
                    };
                }
            }
        }

        // No need to clear the caches because its already done by swapping the snapshot

        Ok(())
    }

    fn swap_snapshot(&mut self, other: Option<Snapshot>) -> Result<Option<Snapshot>, BlockchainError> {
        trace!("swap snapshot");
        Ok(std::mem::replace(&mut self.snapshot, other))
    }
}