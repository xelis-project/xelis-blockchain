use async_trait::async_trait;
use xelis_common::crypto::Hash;
use crate::core::{
    error::BlockchainError,
    storage::{MergeSet, MergeSetProvider, RocksStorage},
};

#[async_trait]
impl MergeSetProvider for RocksStorage {
    async fn get_mergeset(&self, hash: &Hash) -> Result<MergeSet, BlockchainError> {
        self.load_block_metadata(hash)
            .map(|metadata| metadata.mergeset)
    }
}
