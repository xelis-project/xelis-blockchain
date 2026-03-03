use anyhow::Context;
use async_trait::async_trait;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::{MergeSet, MergeSetProvider},
};
use super::super::MemoryStorage;

#[async_trait]
impl MergeSetProvider for MemoryStorage {
    async fn get_mergeset(&self, hash: &Hash) -> Result<MergeSet, BlockchainError> {
        self.blocks.get(hash)
            .map(|entry| entry.mergeset.clone())
            .with_context(|| format!("GHOSTDAG data not found for block {}", hash))
            .map_err(|e| e.into())
    }
}
