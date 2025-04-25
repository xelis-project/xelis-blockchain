use async_trait::async_trait;
use xelis_common::serializer::Serializer;
use crate::core::error::{BlockchainError, DiskContext};

#[async_trait]
pub trait DBProvider {
    // Load a value from the DB
    async fn load_from_db<T: Serializer>(&self, tree: &'static [u8], key: &[u8], context: DiskContext) -> Result<T, BlockchainError>;

    // Load an optional value from the DB
    async fn load_optional_from_db<T: Serializer>(&self, tree: &'static [u8], key: &[u8]) -> Result<Option<T>, BlockchainError>;    
}