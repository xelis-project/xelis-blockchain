use std::collections::{btree_map::{Entry, IntoIter}, BTreeMap};
use bytes::Bytes;

use super::EntryState;

#[derive(Clone, Debug)]
pub struct Changes {
    pub writes: BTreeMap<Bytes, Option<Bytes>>,
}

impl Changes {
    /// Set a key to a new value
    /// Returns the previous value if any
    pub fn insert<K, V>(&mut self, key: K, value: V) -> EntryState<Bytes>
    where
        K: Into<Bytes>,
        V: Into<Bytes>,
    {
        match self.writes.insert(key.into(), Some(value.into())) {
            Some(Some(prev)) => EntryState::Stored(prev),
            Some(None) => EntryState::Deleted,
            None => EntryState::Absent,
        }
    }

    /// Remove a key
    /// If bool return true, we must read from disk
    /// Returns the previous value if any
    pub fn remove<K>(&mut self, key: K) -> EntryState<Bytes>
    where
        K: Into<Bytes>,
    {
        match self.writes.entry(key.into()) {
            Entry::Occupied(mut entry) => {
                let value = entry.get_mut().take();
                match value {
                    Some(v) => EntryState::Stored(v),
                    None => EntryState::Deleted,
                }
            },
            Entry::Vacant(v) => {
                v.insert(None);
                EntryState::Absent
            },
        }
    }

    /// Check if key is present in our batch
    /// Return None if key wasn't overwritten yet
    /// Otherwise, return Some(true) if key is present, Some(false) if it was deleted
    pub fn contains<K>(&self, key: K) -> Option<bool>
    where
        K: AsRef<[u8]>
    {
        self.writes.get(key.as_ref()).map(|v| v.is_some())
    }
}

impl IntoIterator for Changes {
    type Item = (Bytes, Option<Bytes>);
    type IntoIter = IntoIter<Bytes, Option<Bytes>>;

    fn into_iter(self) -> Self::IntoIter {
        self.writes.into_iter()
    }
}

impl Default for Changes {
    fn default() -> Self {
        Self { writes: BTreeMap::new() }
    }
}
