use std::hash::Hash;

use async_trait::async_trait;
use crate::core::{error::BlockchainError, storage::snapshot::Snapshot};

#[async_trait]
pub trait SnapshotProvider {
    type Column: Hash + Eq + Send + Sync + 'static;

    // Check if we have a snapshot already set
    async fn has_snapshot(&self) -> Result<bool, BlockchainError>;

    // Start a commit point
    // This is useful to do some operations before applying the batch
    async fn start_snapshot(&mut self) -> Result<(), BlockchainError>;

    // Apply the batch to the storage
    fn end_snapshot(&mut self, apply: bool) -> Result<(), BlockchainError>;

    fn swap_snapshot(&mut self, other: Option<Snapshot<Self::Column>>) -> Result<Option<Snapshot<Self::Column>>, BlockchainError>;
}