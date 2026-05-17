use async_trait::async_trait;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait SnapshotProvider {
    type Snapshot: Send + Sync + 'static;

    // Check if we have a snapshot already set
    async fn has_snapshot(&self) -> Result<bool, BlockchainError>;

    // Start a commit point
    // This is useful to do some operations before applying the batch
    // If a snapshot exists, it will fork it and returns the previous one.
    async fn start_snapshot(&mut self) -> Result<Option<Self::Snapshot>, BlockchainError>;

    // Apply the batch to the storage
    async fn end_snapshot(&mut self, apply: bool) -> Result<(), BlockchainError>;

    fn swap_snapshot(&mut self, other: Option<Self::Snapshot>) -> Result<Option<Self::Snapshot>, BlockchainError>;
}