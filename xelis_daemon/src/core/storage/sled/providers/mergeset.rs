use async_trait::async_trait;
use xelis_common::crypto::Hash;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{MergeSet, MergeSetProvider, SledStorage},
};

#[async_trait]
impl MergeSetProvider for SledStorage {
    async fn get_mergeset(&self, hash: &Hash) -> Result<MergeSet, BlockchainError> {
        self.load_from_disk(&self.mergeset, hash.as_bytes(), DiskContext::LoadData)
    }
}
