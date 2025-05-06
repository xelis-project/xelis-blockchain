use std::collections::{btree_map::{Entry, IntoIter}, BTreeMap};
use itertools::{Either, Itertools};
use sled::{IVec, Tree};
use xelis_common::serializer::Serializer;

use crate::core::{error::BlockchainError, storage::cache::StorageCache};

pub struct Batch {
    writes: BTreeMap<IVec, Option<IVec>>,
}

impl Default for Batch {
    fn default() -> Self {
        Self { writes: BTreeMap::new() }
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
    pub trees: BTreeMap<IVec, Option<Batch>>,
    pub cache: StorageCache
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            trees: BTreeMap::new(),
            cache: StorageCache::default()
        }
    }
}

impl Snapshot {
    // Create a new snapshot with current counts
    pub fn new(cache: StorageCache) -> Self {
        Self {
            trees: BTreeMap::new(),
            cache
        }
    }

    // Contains a key in the snapshot
    pub fn contains_key(&self, tree: &Tree, key: &[u8]) -> bool {
        self.trees.get(&tree.name())
            .map(|batch| batch.as_ref()
                .map_or(false, |batch| batch.writes.contains_key(key))
            )
            .unwrap_or(false)
    }

    // Contains a key in the snapshot with a value
    // If its deleted, it should return false
    // If its not touched, return None
    pub fn contains_key_with_value(&self, tree: &Tree, key: &[u8]) -> Option<bool> {
        self.trees.get(&tree.name())
            .and_then(|batch| {
                batch.as_ref()
                    .and_then(|batch|
                        batch.writes.get(key)
                            .map(|v| v.is_some())
                    )
            })
    }

    // Read from our snapshot
    pub fn load_optional_from_disk<T: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<Option<T>, BlockchainError> {
        let data = self.trees.get(&tree.name())
            .and_then(|batch| {
                batch.as_ref()
                    .and_then(|batch| batch.writes.get(key))
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
        let batch = self.trees.entry(tree.name())
            .or_insert_with(|| Some(Batch::default()));
        
        match batch {
            Some(batch) => batch.insert(key.into(), value.into()),
            None => {
                let mut b = Batch::default();
                let res = b.insert(key.into(), value.into());
                *batch = Some(b);
                res
            }
        }
    }

    // Remove a key from the snapshot
    // This will mark the entry as None
    // If the key is not found, it will return true to load from the disk
    pub fn remove<K: Into<IVec>>(&mut self, tree: &Tree, key: K) -> (Option<IVec>, bool) {
        let batch = self.trees.entry(tree.name())
            .or_insert_with(|| Some(Batch::default()));

        match batch {
            Some(batch) => batch.remove(key.into()),
            None => (None, false),
        }
    }

    // Get the length of a value using its tree key in the snapshot
    pub fn get_value_size<K: AsRef<[u8]> + ?Sized>(&self, tree: &Tree, key: &K) -> Option<usize> {
        let batch = self.trees.get(&tree.name())?
            .as_ref()?;
        let elem = batch.writes.get(key.as_ref())?.as_ref()?;
        Some(elem.len())
    }

    // Drop the tree by marking it as None
    pub fn drop_tree<V: AsRef<[u8]>>(&mut self, tree_name: V) -> bool {
        self.trees.insert(tree_name.as_ref().into(), None).is_some()
    }

    pub fn scan_prefix(&self, tree: &Tree, prefix: &[u8]) -> impl Iterator<Item = sled::Result<IVec>> {
        match self.trees.get(&tree.name()) {
            Some(Some(entries)) => {
                let original =  tree.scan_prefix(prefix)
                    .keys()
                    .filter_map_ok(|v| {
                        if !entries.writes.contains_key(&v) {
                            Some(v)
                        } else {
                            None
                        }
                    });

                let changes = entries.writes.iter()
                    .filter(|(k, v)| v.is_some() && k.starts_with(prefix))
                    .map(|(k, _)| Ok(k.clone()))
                    .chain(original)
                    .collect::<Vec<_>>()
                    .into_iter();

                Either::Left(changes)
            },
            _ => Either::Right(tree.scan_prefix(prefix).keys())
        }
    }

    pub fn iter(&self, tree: &Tree) -> impl Iterator<Item = sled::Result<(IVec, IVec)>> {
        match self.trees.get(&tree.name()) {
            Some(Some(entries)) => {
                let original = tree.iter()
                    .filter_map_ok(|(k, v)| {
                        if !entries.writes.contains_key(&k) {
                            Some((k, v))
                        } else {
                            None
                        }
                    });

                let changes = entries.writes.iter()
                    .filter_map(|(k, v)| v.clone().map(|v| Ok((k.clone(), v))))
                    .chain(original)
                    .collect::<Vec<_>>()
                    .into_iter();

                Either::Left(changes)
            },
            _ => Either::Right(tree.iter())
        }
    }

    pub fn iter_keys(&self, tree: &Tree) -> impl Iterator<Item = sled::Result<IVec>> {
        match self.trees.get(&tree.name()) {
            Some(Some(entries)) => {
                let original = tree.iter()
                    .keys()
                    .filter_map_ok(|k| {
                        if !entries.writes.contains_key(&k) {
                            Some(k)
                        } else {
                            None
                        }
                    });

                let changes = entries.writes.iter()
                    .filter_map(|(k, v)| v.as_ref().map(|_| Ok(k.clone())))
                    .chain(original)
                    .collect::<Vec<_>>()
                    .into_iter();

                Either::Left(changes)
            },
            _ => Either::Right(tree.iter().keys())
        }
    }
}