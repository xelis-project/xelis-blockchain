use async_trait::async_trait;
use log::trace;
use crate::core::{
    error::BlockchainError,
    storage::{SledStorage, Storage}
};
#[async_trait]
pub trait CommitPointProvider {
    // Start a commit point
    // This is useful to do some operations before applying the batch
    async fn start_commit_point(&mut self) -> Result<(), BlockchainError>;

    // Apply the batch to the storage
    async fn end_commit_point(&mut self, apply: bool) -> Result<(), BlockchainError>;
}

#[async_trait]
impl CommitPointProvider for SledStorage {

    async fn start_commit_point(&mut self) -> Result<(), BlockchainError> {
        trace!("Starting commit point");
        if self.snapshot.is_some() {
            return Err(BlockchainError::CommitPointAlreadyStarted);
        }

        self.snapshot = Some(Default::default());
        Ok(())
    }

    async fn end_commit_point(&mut self, apply: bool) -> Result<(), BlockchainError> {
        trace!("end commit point");

        let snapshot = self.snapshot.take().ok_or(BlockchainError::CommitPointNotStarted)?;
        if apply {
            for (tree, batch) in snapshot.finalize().into_iter() {
                trace!("Applying batch to tree {:?}", tree);
                let tree = self.db.open_tree(tree)?;
                for (key, value) in batch.into_iter() {
                    match value {
                        Some(value) => tree.insert(key, value)?,
                        None => tree.remove(key)?,
                    };
                }
            }
    
            self.clear_caches().await?;
        }

        Ok(())
    }
}