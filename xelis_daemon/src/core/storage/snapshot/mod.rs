use std::collections::{hash_map::IntoIter, HashMap};
// use async_trait::async_trait;
use sled::IVec;

use super::Storage;

pub struct Batch {
    writes: HashMap<IVec, Option<IVec>>,
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
pub struct Snapshot<'a, S: Storage> {
    storage: &'a S,
    trees: HashMap<IVec, Batch>
}

// This is the final struct to get rid of the borrowed Storage
// to be able to borrow it again mutably and apply changes
pub struct BatchApply {
    trees: HashMap<IVec, Batch>
}

impl<'a, S: Storage> Snapshot<'a, S> {
    pub fn new(storage: &'a S) -> Self {
        Self { storage, trees: HashMap::new() }
    }

    pub fn storage(&self) -> &'a S {
        &self.storage
    }

    // Transforms the snapshot into a BatchApply
    pub fn finalize(self) -> BatchApply {
        BatchApply { trees: self.trees }
    }
}

impl IntoIterator for BatchApply {
    type Item = (IVec, Batch);
    type IntoIter = IntoIter<IVec, Batch>;

    fn into_iter(self) -> Self::IntoIter {
        self.trees.into_iter()
    }
}

// #[async_trait]
// impl<'a, S: Storage> Storage for Snapshot<'a, S> {
    
// }