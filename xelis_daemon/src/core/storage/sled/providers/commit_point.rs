use async_trait::async_trait;
use log::{debug, trace};
use crate::core::{
    error::BlockchainError,
    storage::{CacheProvider, CommitPointProvider, SledStorage, sled::Snapshot}
};

#[async_trait]
impl CommitPointProvider for SledStorage {
    // Check if we have a commit point already set
    async fn has_commit_point(&self) -> Result<bool, BlockchainError> {
        Ok(self.snapshot.is_some())
    }

    async fn start_commit_point(&mut self) -> Result<(), BlockchainError> {
        trace!("Starting commit point");
        if self.snapshot.is_some() {
            return Err(BlockchainError::CommitPointAlreadyStarted);
        }

        let snapshot = Snapshot::new(self.cache.clone_mut());
        self.snapshot = Some(snapshot);
        Ok(())
    }

    async fn end_commit_point(&mut self, apply: bool) -> Result<(), BlockchainError> {
        trace!("end commit point");
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
        } else {
            debug!("Clearing caches due to invalidation of the commit point");
            self.clear_caches().await?;
        }

        Ok(())
    }
}