use std::collections::{btree_map::{Entry, IntoIter}, BTreeMap};
use anyhow::Context;
use bytes::Bytes;
use itertools::{Itertools, Either};
use xelis_common::serializer::Serializer;

use crate::core::error::BlockchainError;

use super::Column;

pub struct Batch {
    writes: BTreeMap<Bytes, Option<Bytes>>,
}

impl Batch {
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
            Entry::Vacant(_) => (None, true),
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

impl IntoIterator for Batch {
    type Item = (Bytes, Option<Bytes>);
    type IntoIter = IntoIter<Bytes, Option<Bytes>>;

    fn into_iter(self) -> Self::IntoIter {
        self.writes.into_iter()
    }
}

impl Default for Batch {
    fn default() -> Self {
        Self { writes: BTreeMap::new() }
    }
}

pub struct Snapshot {
    pub columns: BTreeMap<Column, Batch>,
}

impl Snapshot {
    pub fn new() -> Self {
        Self {
            columns: BTreeMap::new(),
        }
    }
    pub fn delete<K: Into<Bytes>>(&mut self, column: Column, key: K) {
        self.columns.entry(column)
            .or_insert_with(Batch::default)
            .remove(key);
    }

    pub fn put<K: Into<Bytes>, V: Into<Bytes>>(&mut self, column: Column, key: K, value: V) {
        self.columns.entry(column)
            .or_insert_with(Batch::default)
            .insert(key, value);
    }

    pub fn contains<K: AsRef<[u8]>>(&self, column: Column, key: K) -> Option<bool> {
        let batch = self.columns.get(&column)?;
        batch.contains(key)
    }

    // Lazy iterator over a prefix
    pub fn iter_prefix<'a, K: Serializer + 'a, V: Serializer + 'a, P: AsRef<[u8]> + 'a>(&'a self, column: Column, prefix: P, iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a {
        match self.columns.get(&column) {
            Some(tree) => {
                Either::Left(iterator.filter_map_ok(|(k, v)| {
                        if tree.writes.contains_key(&*k) {
                            Some((k, v))
                        } else {
                            None
                        }
                    })
                    .map(|k| {
                        let (key, value) = k.context("Internal error in snapshot iter_prefix")?;
                        let k = K::from_bytes(&key)?;
                        let v = V::from_bytes(&value)?;

                        Ok((k, v))
                    })
                    .chain(
                        tree.writes.iter()
                            .filter_map(move |(k, v)| {
                                if k.starts_with(prefix.as_ref()) {
                                    v.as_ref().map(|v| (k, v))
                                } else {
                                    None
                                }
                            })
                            .map(|(k, v)| {
                                let key = K::from_bytes(&k)?;
                                let value = V::from_bytes(&v)?;
                                Ok((key, value))
                            })
                    ))
            },
            None => Either::Right(std::iter::empty())
        }
    }

    // Lazy iterator for keys only over a prefix
    pub fn iter_keys_prefix<'a, K: Serializer + 'a, P: AsRef<[u8]> + 'a>(&'a self, column: Column, prefix: P, iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a) -> impl Iterator<Item = Result<K, BlockchainError>> + 'a {
        match self.columns.get(&column) {
            Some(tree) => {
                Either::Left(iterator.filter_map_ok(|(k, v)| {
                        if tree.writes.contains_key(&*k) {
                            Some((k, v))
                        } else {
                            None
                        }
                    })
                    .map(|k| {
                        let (key, _) = k.context("Internal error in snapshot iter_keys_prefix")?;
                        let k = K::from_bytes(&key)?;

                        Ok(k)
                    })
                    .chain(
                        tree.writes.iter()
                            .filter_map(move |(k, v)| {
                                if k.starts_with(prefix.as_ref()) {
                                    v.as_ref().map(|_| k)
                                } else {
                                    None
                                }
                            })
                            .map(|k| {
                                let key = K::from_bytes(&k)?;
                                Ok(key)
                            })
                    ))
            },
            None => Either::Right(std::iter::empty())
        }
    }

    // Lazy iterator 
    pub fn iter<'a, K: Serializer + 'a, V: Serializer + 'a>(&'a self, column: Column, iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a {
        match self.columns.get(&column) {
            Some(tree) => {
                Either::Left(iterator.filter_map_ok(|(k, v)| {
                        if tree.writes.contains_key(&*k) {
                            Some((k, v))
                        } else {
                            None
                        }
                    })
                    .map(|k| {
                        let (key, value) = k.context("Internal error in snapshot iter")?;
                        let k = K::from_bytes(&key)?;
                        let v = V::from_bytes(&value)?;

                        Ok((k, v))
                    })
                    .chain(
                        tree.writes.iter()
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
                            .map(|(k, v)| {
                                let key = K::from_bytes(&k)?;
                                let value = V::from_bytes(&v)?;
                                Ok((key, value))
                            })
                    ))
            },
            None => Either::Right(std::iter::empty())
        }
    }

    // Lazy iterator over keys only
    pub fn iter_keys<'a, K: Serializer + 'a>(&'a self, column: Column, iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a) -> impl Iterator<Item = Result<K, BlockchainError>> + 'a {
        match self.columns.get(&column) {
            Some(tree) => {
                Either::Left(iterator.filter_map_ok(|(k, _)| {
                        if tree.writes.contains_key(&*k) {
                            Some(k)
                        } else {
                            None
                        }
                    })
                    .map(|k| {
                        let key = k.context("Internal error in snapshot iter_keys")?;
                        Ok(K::from_bytes(&key)?)
                    })
                    .chain(
                        tree.writes.iter()
                            .filter_map(|(k, v)| v.as_ref().map(|_| k))
                            .map(|k| Ok(K::from_bytes(&k)?))
                    ))
            },
            None => Either::Right(std::iter::empty())
        }
    }
}