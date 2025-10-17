use std::collections::{btree_map::{Entry, IntoIter}, BTreeMap};
use bytes::Bytes;

#[derive(Clone, Debug)]
pub struct Changes {
    pub writes: BTreeMap<Bytes, Option<Bytes>>,
}

impl Changes {
    /// Set a key to a new value
    pub fn insert<K, V>(&mut self, key: K, value: V) -> Option<Bytes>
    where
        K: Into<Bytes>,
        V: Into<Bytes>,
    {
        self.writes.insert(key.into(), Some(value.into())).flatten()
    }

    /// Remove a key
    /// If bool return true, we must read from disk
    pub fn remove<K>(&mut self, key: K) -> (Option<Bytes>, bool)
    where
        K: Into<Bytes>,
    {
        match self.writes.entry(key.into()) {
            Entry::Occupied(mut entry) => {
                let value = entry.get_mut().take();
                (value, false)
            },
            Entry::Vacant(v) => {
                v.insert(None);
                (None, true)
            },
        }
    }

    /// Check if key is present in our batch
    /// Return None if key wasn't overwritten yet
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
