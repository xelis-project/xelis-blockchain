use std::collections::{hash_map::{Entry, IntoIter}, HashMap};
use sled::{IVec, Tree};
use xelis_common::serializer::Serializer;

use crate::core::error::BlockchainError;

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
    pub fn insert<K, V>(&mut self, key: K, value: V) -> Option<IVec>
    where
        K: Into<IVec>,
        V: Into<IVec>,
    {
        self.writes.insert(key.into(), Some(value.into())).flatten()
    }

    /// Remove a key
    pub fn remove<K>(&mut self, key: K) -> (Option<IVec>, bool)
    where
        K: Into<IVec>,
    {
        match self.writes.entry(key.into()) {
            Entry::Occupied(mut entry) => {
                let value = entry.get_mut().take();
                (value, false)
            },
            Entry::Vacant(_) => (None, true),
        }
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
pub struct Snapshot {
    trees: HashMap<IVec, Batch>
}

// This is the final struct to get rid of the borrowed Storage
// to be able to borrow it again mutably and apply changes
pub struct BatchApply {
    trees: HashMap<IVec, Batch>
}

impl Default for Snapshot {
    fn default() -> Self {
        Self { trees: HashMap::new() }
    }
}

impl Snapshot {
    // Contains a key in the snapshot
    pub fn contains_key(&self, tree: &Tree, key: &[u8]) -> bool {
        self.trees.get(&tree.name())
            .map(|batch| batch.writes.contains_key(key))
            .unwrap_or(false)
    }

    // Contains a key in the snapshot with a value
    // If its deleted, it should return false
    // If its empty, return None
    pub fn contains_key_with_value(&self, tree: &Tree, key: &[u8]) -> Option<bool> {
        self.trees.get(&tree.name())
            .and_then(|batch| {
                batch.writes.get(key)
            })
            .map(|value| value.is_some())
    }

    // Read from our snapshot
    pub fn load_optional_from_disk<T: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<Option<T>, BlockchainError> {
        let data = self.trees.get(&tree.name())
            .and_then(|batch| {
                batch.writes.get(key)
            })
            .and_then(Option::as_ref);

        match data {
            Some(data) => Ok(Some(T::from_bytes(data)?)),
            None => Ok(None),
        }
    }

    // Insert a key into the snapshot
    // Returns the previous value if it exists
    pub fn insert<K: Into<IVec>, V: Into<IVec>>(&mut self, tree: &Tree, key: K, value: V) -> Option<IVec> {
        self.trees.entry(tree.name())
            .or_insert_with(Batch::default)
            .insert(key.into(), value.into())
    }

    // Remove a key from the snapshot
    // This will mark the entry as None
    // If the key is not found, it will return true to load from the disk
    pub fn remove<K: Into<IVec>>(&mut self, tree: &Tree, key: K) -> (Option<IVec>, bool) {
        let batch = self.trees.entry(tree.name())
            .or_insert_with(Batch::default);

        batch.remove(key.into())
    }

    // Get the length of a value using its tree key in the snapshot
    pub fn get_len_for<K: AsRef<[u8]> + ?Sized>(&self, tree: &Tree, key: &K) -> Option<usize> {
        let batch = self.trees.get(&tree.name())?;
        let elem = batch.writes.get(key.as_ref())?.as_ref()?;
        Some(elem.len())
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