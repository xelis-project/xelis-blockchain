use async_trait::async_trait;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait CommitPointProvider {
    // Start a commit point
    // This is useful to do some operations before applying the batch
    async fn start_commit_point(&mut self) -> Result<(), BlockchainError>;

    // Apply the batch to the storage
    async fn end_commit_point(&mut self, apply: bool) -> Result<(), BlockchainError>;
}