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

    // Lazy interator over keys and values
    // Both are parsed from bytes
    // It will fallback on the disk iterator
    // if the key is not present in the batch
    pub fn iter<'a, K, V, P>(
        &'a self,
        column: Column,
        prefix: Option<P>,
        iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a,
    ) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
        P: AsRef<[u8]> + 'a,
    {
        match self.columns.get(&column) {
            Some(tree) => {
                let disk_iter = iterator
                    .filter_map_ok(|(k, v)| {
                        if tree.writes.contains_key(&*k) {
                            Some((k, v))
                        } else {
                            None
                        }
                    })
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;
                        Ok((K::from_bytes(&key)?, V::from_bytes(&value)?))
                    });

                let mem_iter = tree.writes.iter().map(move |(k, v)| {
                    if let Some(val) = v {
                        if prefix.as_ref().map_or(true, |p| k.starts_with(p.as_ref())) {
                            Ok(Some((
                                K::from_bytes(k)?,
                                V::from_bytes(val)?,
                            )))
                        } else {
                            Ok(None)
                        }
                    } else {
                        Ok(None)
                    }
                }).filter_map(Result::transpose);

                Either::Left(disk_iter.chain(mem_iter))
            }
            None => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;
                        Ok((K::from_bytes(&key)?, V::from_bytes(&value)?))
                    });

                Either::Right(disk_iter)
            }
        }
    }

    // Similar to `iter` but only for keys
    pub fn iter_keys<'a, K, P>(
        &'a self,
        column: Column,
        prefix: Option<P>,
        iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a,
    ) -> impl Iterator<Item = Result<K, BlockchainError>> + 'a
    where
        K: Serializer + 'a,
        P: AsRef<[u8]> + 'a,
    {
        match self.columns.get(&column) {
            Some(tree) => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, _) = res.context("Internal error in snapshot iterator")?;

                        // Snapshot doesn't contains the key,
                        // We can use the one from disk
                        if !tree.writes.contains_key(&*key) {
                            Ok(Some(K::from_bytes(&key)?))
                        } else {
                            Ok(None)
                        }
                    }).filter_map(Result::transpose);

                let mem_iter = tree.writes.iter()
                    .map(move |(k, v)| {
                        if v.is_some() {
                            if prefix.as_ref().map_or(true, |p| k.starts_with(p.as_ref())) {
                                return Ok(Some(K::from_bytes(k)?))
                            }
                        }

                        Ok(None)
                    }).filter_map(Result::transpose);

                Either::Left(disk_iter.chain(mem_iter))
            }
            None => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, _) = res.context("Internal error in snapshot iterator")?;
                        Ok(K::from_bytes(&key)?)
                    });

                Either::Right(disk_iter)
            }
        }
    }
}