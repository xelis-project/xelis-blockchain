use std::collections::{hash_map::IntoIter, HashMap};
use sled::IVec;
use xelis_common::serializer::Serializer;

use crate::core::error::{BlockchainError, DiskContext};

use super::{DBProvider, Storage};

pub struct Batch {
    writes: HashMap<IVec, Option<IVec>>,
}

impl Default for Batch {
    fn default() -> Self {
        Self { writes: HashMap::new() }
    }
}

impl Batch {
    /// Set a key to a new value
    pub fn insert<K, V>(&mut self, key: K, value: V)
    where
        K: Into<IVec>,
        V: Into<IVec>,
    {
        self.writes.insert(key.into(), Some(value.into()));
    }

    /// Remove a key
    pub fn remove<K>(&mut self, key: K)
    where
        K: Into<IVec>,
    {
        self.writes.insert(key.into(), None);
    }
}

impl IntoIterator for Batch {
    type Item = (IVec, Option<IVec>);
    type IntoIter = IntoIter<IVec, Option<IVec>>;

    fn into_iter(self) -> Self::IntoIter {
        self.writes.into_iter()
    }
}

// Create a snapshot of the current state of the DB
// We track all the changes made to the DB since the snapshot was created
// So we can apply them to the DB or rollback them
pub struct Snapshot<'a, S: Storage + DBProvider> {
    storage: &'a S,
    trees: HashMap<&'static [u8], Batch>
}

// This is the final struct to get rid of the borrowed Storage
// to be able to borrow it again mutably and apply changes
pub struct BatchApply {
    trees: HashMap<&'static [u8], Batch>
}

impl<'a, S: Storage + DBProvider> Snapshot<'a, S> {
    pub fn new(storage: &'a S) -> Self {
        Self { storage, trees: HashMap::new() }
    }

    pub fn storage(&self) -> &'a S {
        &self.storage
    }

    // Read from our snapshot
    // If not found, read from the disk
    pub async fn load_from_disk<T: Serializer>(&self, tree: &'static [u8], key: &[u8], context: DiskContext) -> Result<T, BlockchainError> {
        if let Some(batch) = self.trees.get(tree) {
            if let Some(value) = batch.writes.get(key) {
                return match value {
                    Some(value) => Ok(T::from_bytes(value)?),
                    None => Err(BlockchainError::NotFoundOnDisk(context)),
                }
            }
        }

        self.storage.load_from_db(tree, key, context).await
    }

    pub fn insert<T: Into<IVec>, K: Into<IVec>, V: Into<IVec>>(&mut self, tree: &'static [u8], key: K, value: V) {
        self.trees.entry(tree)
            .or_insert_with(Batch::default)
            .insert(key.into(), value.into());
    }

    // Transforms the snapshot into a BatchApply
    pub fn finalize(self) -> BatchApply {
        BatchApply { trees: self.trees }
    }
}

impl IntoIterator for BatchApply {
    type Item = (&'static [u8], Batch);
    type IntoIter = IntoIter<&'static [u8], Batch>;

    fn into_iter(self) -> Self::IntoIter {
        self.trees.into_iter()
    }
}