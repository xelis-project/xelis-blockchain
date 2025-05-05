use async_trait::async_trait;
use xelis_common::serializer::Serializer;
use log::trace;
use crate::core::{error::{BlockchainError, DiskContext}, storage::{DBProvider, SledStorage}};

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