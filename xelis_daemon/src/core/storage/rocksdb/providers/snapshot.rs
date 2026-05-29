use async_trait::async_trait;
use log::trace;
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Snapshot,
        RocksStorage,
        SnapshotProvider,
    }
};

#[async_trait]
impl SnapshotProvider for RocksStorage {
    type Snapshot = Snapshot;

    // Check if we have a commit point already set
    async fn has_snapshot(&self) -> Result<bool, BlockchainError> {
        trace!("has snapshot");
        Ok(self.snapshot.is_some())
    }

    async fn start_snapshot(&mut self) -> Result<Option<Snapshot>, BlockchainError> {
        trace!("start snapshot");
        let previous_snapshot = self.snapshot.clone();

        if previous_snapshot.is_none() {
            trace!("Creating new snapshot");
            let snapshot = Snapshot::new(self.cache.clone_mut());
            self.snapshot = Some(snapshot);
        }

        Ok(previous_snapshot)
    }

    async fn end_snapshot(&mut self, apply: bool) -> Result<(), BlockchainError> {
        trace!("end snapshot");
        let snapshot = self.snapshot.take()
            .ok_or(BlockchainError::CommitPointNotStarted)?;

        if apply {
            trace!("applying snapshot");
            self.run_blocking_mut(|s| {
                for (column, batch) in snapshot.trees {
                    for (key, value) in batch {
                        if let Some(value) = value {
                            s.insert_into_disk(column, &key.as_ref(), &value.as_ref())?;
                        } else {
                            s.remove_from_disk(column, &key.as_ref())?;
                        }
                    }
                }

                Ok(())
            })?;

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