use async_trait::async_trait;
use xelis_common::serializer::Serializer;
use log::trace;
use crate::core::{error::{BlockchainError, DiskContext}, storage::SledStorage};

#[async_trait]
pub trait DBProvider {
    // Load a value from the DB
    async fn load_from_db<T: Serializer>(&self, tree: &'static [u8], key: &[u8], context: DiskContext) -> Result<T, BlockchainError>;

    // Load an optional value from the DB
    async fn load_optional_from_db<T: Serializer>(&self, tree: &'static [u8], key: &[u8]) -> Result<Option<T>, BlockchainError>;    
}

#[async_trait]
impl DBProvider for SledStorage {
    async fn load_from_db<T: Serializer>(&self, tree: &'static [u8], key: &[u8], context: DiskContext) -> Result<T, BlockchainError> {
        let tree = self.db.open_tree(tree)?;
        self.load_from_disk(&tree, key, context)
    }

    async fn load_optional_from_db<T: Serializer>(&self, tree: &'static [u8], key: &[u8]) -> Result<Option<T>, BlockchainError> {
        trace!("load optional from db, tree: {:?}, key: {:?}", tree, key);
        let tree = self.db.open_tree(tree)?;
        self.load_optional_from_disk(&tree, key)
    }
}