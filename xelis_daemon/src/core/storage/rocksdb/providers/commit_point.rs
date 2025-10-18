use async_trait::async_trait;
use log::{debug, trace};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Snapshot,
        CacheProvider,
        CommitPointProvider,
        RocksStorage
    }
};

#[async_trait]
impl CommitPointProvider for RocksStorage {
    // Check if we have a commit point already set
    async fn has_commit_point(&self) -> Result<bool, BlockchainError> {
        Ok(self.snapshot.is_some())
    }

    async fn start_commit_point(&mut self) -> Result<(), BlockchainError> {
        trace!("starting commit point");
        if self.snapshot.is_some() {
            return Err(BlockchainError::CommitPointAlreadyStarted);
        }

        self.snapshot = Some(Snapshot::new(self.cache.clone_mut()));
        Ok(())
    }

    async fn end_commit_point(&mut self, apply: bool) -> Result<(), BlockchainError> {
        trace!("end commit point");
        let snapshot = self.snapshot.take()
            .ok_or(BlockchainError::CommitPointNotStarted)?;

        if apply {
            trace!("applying commit point");
            for (column, batch) in snapshot.trees {
                for (key, value) in batch {
                    if let Some(value) = value {
                        self.insert_into_disk(column, &key.as_ref(), &value.as_ref())?;
                    } else {
                        self.remove_from_disk(column, &key.as_ref())?;
                    }
                }
            }
        } else {
            debug!("Clearing caches due to invalidation of the commit point");
            self.clear_caches().await?;
        }

        Ok(())
    }
}