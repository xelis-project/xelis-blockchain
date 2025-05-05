use async_trait::async_trait;
use log::{debug, trace};
use crate::core::{
    error::BlockchainError,
    storage::{rocksdb::RocksSnapshot, CacheProvider, CommitPointProvider, RocksStorage}
};

#[async_trait]
impl CommitPointProvider for RocksStorage {
    async fn start_commit_point(&mut self) -> Result<(), BlockchainError> {
        trace!("Starting commit point");
        if self.snapshot.is_some() {
            return Err(BlockchainError::CommitPointAlreadyStarted);
        }

        self.snapshot = Some(RocksSnapshot::new());
        Ok(())
    }

    async fn end_commit_point(&mut self, apply: bool) -> Result<(), BlockchainError> {
        trace!("end commit point");
        let snapshot = self.snapshot.take()
            .ok_or(BlockchainError::CommitPointNotStarted)?;

        if apply {
            for (column, batch) in snapshot.columns {
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