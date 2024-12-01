use async_trait::async_trait;
use log::trace;
use crate::core::{
    error::BlockchainError,
    storage::{snapshot::BatchApply, SledStorage, Storage}
};
#[async_trait]
pub trait BatchApplicator {
    // Apply a batch of changes to the storage
    async fn apply_batch(&mut self, batch: BatchApply) -> Result<(), BlockchainError>;
}

#[async_trait]
impl BatchApplicator for SledStorage {
    async fn apply_batch(&mut self, batch: BatchApply) -> Result<(), BlockchainError> {
        trace!("Applying batch to storage");
        for (tree, batch) in batch.into_iter() {
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

        Ok(())
    }
}