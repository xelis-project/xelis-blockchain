use async_trait::async_trait;
use log::trace;
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, Snapshot},
        RocksStorage,
        SnapshotProvider,
    }
};

#[async_trait]
impl SnapshotProvider for RocksStorage {
    type Column = Column;

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

        self.snapshot = Some(Snapshot::new(self.cache.clone_mut()));
        Ok(())
    }

    fn end_snapshot(&mut self, apply: bool) -> Result<(), BlockchainError> {
        trace!("end snapshot");
        let snapshot = self.snapshot.take()
            .ok_or(BlockchainError::CommitPointNotStarted)?;

        if apply {
            trace!("applying snapshot");
            for (column, batch) in snapshot.trees {
                for (key, value) in batch {
                    if let Some(value) = value {
                        self.insert_into_disk(column, &key.as_ref(), &value.as_ref())?;
                    } else {
                        self.remove_from_disk(column, &key.as_ref())?;
                    }
                }
            }

            self.cache = snapshot.cache;
        }

        // No need to clear the caches because its already done by swapping the snapshot

        Ok(())
    }

    fn swap_snapshot(&mut self, other: Option<Snapshot>) -> Result<Option<Snapshot>, BlockchainError> {
        trace!("swap snapshot");
        Ok(std::mem::replace(&mut self.snapshot, other))
    }
}