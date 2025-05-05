use async_trait::async_trait;
use log::{debug, trace};
use crate::core::{
    error::BlockchainError,
    storage::{CacheProvider, CommitPointProvider, SledStorage, SledSnapshot}
};

#[async_trait]
impl CommitPointProvider for SledStorage {

    async fn start_commit_point(&mut self) -> Result<(), BlockchainError> {
        trace!("Starting commit point");
        if self.snapshot.is_some() {
            return Err(BlockchainError::CommitPointAlreadyStarted);
        }

        let snapshot = SledSnapshot::new(self.cache.clone());
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
                trace!("Applying batch to tree {:?}", tree);
                match batch {
                    Some(batch) => {
                        let tree = self.db.open_tree(tree)?;
                        for (key, value) in batch.into_iter() {
                            match value {
                                Some(value) => tree.insert(key, value)?,
                                None => tree.remove(key)?,
                            };
                        }
                    },
                    None => {
                        trace!("Dropping tree {:?}", tree);
                        self.db.drop_tree(tree)?;
                    }
                };
            }
        } else {
            debug!("Clearing caches due to invalidation of the commit point");
            self.clear_caches().await?;
        }

        Ok(())
    }
}