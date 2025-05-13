use std::collections::{btree_map::{Entry, IntoIter}, BTreeMap};
use anyhow::Context;
use bytes::Bytes;
use itertools::Either;
use rocksdb::Direction;
use xelis_common::serializer::Serializer;

use crate::core::error::BlockchainError;

use super::{Column, IteratorMode};

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

    pub fn get<'a, K: AsRef<[u8]>>(&'a self, column: Column, key: K) -> Option<Option<&'a Bytes>> {
        let batch = self.columns.get(&column)?;
        batch.writes.get(key.as_ref())
            .map(|v| v.as_ref())
    }

    pub fn get_size<'a, K: AsRef<[u8]>>(&'a self, column: Column, key: K) -> Option<Option<usize>> {
        let batch = self.columns.get(&column)?;
        batch.writes.get(key.as_ref())
            .map(|v| v.as_ref().map(|v| v.len()))
    }

    pub fn contains<K: AsRef<[u8]>>(&self, column: Column, key: K) -> Option<bool> {
        let batch = self.columns.get(&column)?;
        batch.contains(key)
    }

    // Lazy interator over keys and values
    // Both are parsed from bytes
    // It will fallback on the disk iterator
    // if the key is not present in the batch
    // Note that this iterator is lazy and is
    // not allocating or copying any data from it!
    pub fn lazy_iter<'a, K, V>(
        &'a self,
        column: Column,
        mode: IteratorMode,
        iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a,
    ) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
    {
        match self.columns.get(&column) {
            Some(tree) => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;

                        // Snapshot doesn't contains the key,
                        // We can use the one from disk
                        if !tree.writes.contains_key(&*key) {
                            Ok(Some((K::from_bytes(&key)?, V::from_bytes(&value)?)))
                        } else {
                            Ok(None)
                        }
                    }).filter_map(Result::transpose);

                let mem_iter = match mode {
                    IteratorMode::Start => Either::Left(Either::Left(tree.writes.iter().filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))),
                    IteratorMode::End => Either::Left(Either::Right(tree.writes.iter().rev().filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))),
                    IteratorMode::WithPrefix(prefix, direction) => {
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.iter()),
                            Direction::Reverse => Either::Right(tree.writes.iter().rev())
                        };

                        let cloned = prefix.to_vec();
                        Either::Right(Either::Left(iter.filter_map(move |(k, v)| {
                            if let Some(v) = v {
                                if k.starts_with(&cloned) {
                                    return Some((k, v))
                                }
                            }

                            None
                        })))
                    },
                    IteratorMode::From(start, direction) => {
                        let start = Bytes::from(start.to_vec());
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.range(start..)),
                            Direction::Reverse => Either::Right(tree.writes.range(start..).rev())
                        };

                        Either::Right(Either::Right(iter.filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))))
                    }
                };

                let mem_iter = mem_iter.into_iter()
                    .map(|(k, v)| Ok((K::from_bytes(k)?, V::from_bytes(v)?)));

                Either::Left(disk_iter.chain(mem_iter))
            },
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
    // Note that this iterator is lazy and is
    // not allocating or copying any data from it!
    pub fn lazy_iter_keys<'a, K>(
        &'a self,
        column: Column,
        mode: IteratorMode,
        iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a,
    ) -> impl Iterator<Item = Result<K, BlockchainError>> + 'a
    where
        K: Serializer + 'a
    {
        self.lazy_iter::<K, ()>(column, mode, iterator)
            .map(|res| res.map(|(k, _)| k))
    }

    // Iterator over keys and values
    // Both are parsed from bytes
    // It will fallback on the disk iterator
    // if the key is not present in the batch
    // NOTE: this iterator will copy and allocate
    // the data from the iterators to prevent borrowing
    // current snapshot.
    pub fn iter_owned<'a, K, V>(
        &self,
        column: Column,
        mode: IteratorMode,
        iterator: impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + 'a,
    ) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
    {
        match self.columns.get(&column) {
            Some(tree) => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;

                        // Snapshot doesn't contains the key,
                        // We can use the one from disk
                        if !tree.writes.contains_key(&*key) {
                            Ok(Some((K::from_bytes(&key)?, V::from_bytes(&value)?)))
                        } else {
                            Ok(None)
                        }
                    }).filter_map(Result::transpose);

                let mem_iter = match mode {
                    IteratorMode::Start => Either::Left(Either::Left(tree.writes.iter().filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))),
                    IteratorMode::End => Either::Left(Either::Right(tree.writes.iter().rev().filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))),
                    IteratorMode::WithPrefix(prefix, direction) => {
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.iter()),
                            Direction::Reverse => Either::Right(tree.writes.iter().rev())
                        };

                        let cloned = prefix.to_vec();
                        Either::Right(Either::Left(iter.filter_map(move |(k, v)| {
                            if let Some(v) = v {
                                if k.starts_with(&cloned) {
                                    return Some((k, v))
                                }
                            }

                            None
                        })))
                    },
                    IteratorMode::From(start, direction) => {
                        let start = Bytes::from(start.to_vec());
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.range(start..)),
                            Direction::Reverse => Either::Right(tree.writes.range(start..).rev())
                        };

                        Either::Right(Either::Right(iter.filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))))
                    }
                };

                let mem_iter = mem_iter.into_iter()
                    .map(|(k, v)| Ok((K::from_bytes(k)?, V::from_bytes(v)?)));

                Either::Left(disk_iter.chain(mem_iter).collect::<Vec<_>>().into_iter())
            },
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
}