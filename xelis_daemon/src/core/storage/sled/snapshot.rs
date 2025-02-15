use std::collections::{hash_map::{Entry, IntoIter}, HashMap};
use itertools::{Either, Itertools};
use sled::{IVec, Tree};
use xelis_common::serializer::Serializer;

use crate::core::{error::BlockchainError, storage::Tips};

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
    trees: HashMap<IVec, Option<Batch>>,
    pub(crate) assets_count: u64,
    // Count of accounts
    pub(crate) accounts_count: u64,
    // Count of transactions
    pub(crate) transactions_count: u64,
    // Count of blocks
    pub(crate) blocks_count: u64,
    // Count of blocks added in chain
    pub(crate) blocks_execution_count: u64,
    // Count of contracts
    pub(crate) contracts_count: u64,
    // Tips cache
    pub(crate) tips_cache: Tips
}

// This is the final struct to get rid of the borrowed Storage
// to be able to borrow it again mutably and apply changes
pub struct BatchApply {
    trees: HashMap<IVec, Option<Batch>>
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            trees: HashMap::new(),
            assets_count: 0,
            accounts_count: 0,
            transactions_count: 0,
            blocks_count: 0,
            blocks_execution_count: 0,
            contracts_count: 0,
            tips_cache: Tips::new(),
        }
    }
}

impl Snapshot {
    // Create a new snapshot with current counts
    pub fn new(assets_count: u64, accounts_count: u64, transactions_count: u64, blocks_count: u64, blocks_execution_count: u64, contracts_count: u64, tips_cache: Tips) -> Self {
        Self {
            trees: HashMap::new(),
            assets_count,
            accounts_count,
            transactions_count,
            blocks_count,
            blocks_execution_count,
            contracts_count,
            tips_cache
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

    // Transforms the snapshot into a BatchApply
    pub fn finalize(self) -> BatchApply {
        BatchApply { trees: self.trees }
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
}

impl IntoIterator for BatchApply {
    type Item = (IVec, Option<Batch>);
    type IntoIter = IntoIter<IVec, Option<Batch>>;

    fn into_iter(self) -> Self::IntoIter {
        self.trees.into_iter()
    }
}