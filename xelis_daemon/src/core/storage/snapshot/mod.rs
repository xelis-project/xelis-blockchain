mod changes;
mod iterator_mode;
mod bytes_view;
mod wrapper;

use std::{
    collections::HashMap,
    error::Error as StdError,
    hash::Hash
};

use anyhow::Context;
use bytes::Bytes;
use itertools::Either;
use xelis_common::{serializer::Serializer};
use crate::core::{
    error::BlockchainError,
    storage::{cache::StorageCache, snapshot::changes::Changes}
};

pub use iterator_mode::*;
pub use bytes_view::*;
pub use wrapper::*;

pub enum EntryState<T> {
    // Has been added/modified in our snapshot
    Stored(T),
    // Has been deleted in our snapshot
    Deleted,
    // Not present in our snapshot
    // Must fallback on disk
    Absent
}

// Snapshot is made to be clonable and mutable
// It holds a set of changes per column/tree.
// To clone it, it require to be mutable to clone the cache too.
// Changes are stored as Bytes to avoid serialization/deserialization
// until we need to read them and to also have cheap copies.
#[derive(Debug)]
pub struct Snapshot<C: Hash + Eq> {
    pub trees: HashMap<C, Changes>,
    pub cache: StorageCache,
}

impl<C: Hash + Eq + Clone> Snapshot<C> {
    pub fn clone_mut(&mut self) -> Self {
        Self {
            trees: self.trees.clone(),
            cache: self.cache.clone_mut(),
        }
    }
}

impl<C: Hash + Eq + Clone> Clone for Snapshot<C> {
    fn clone(&self) -> Self {
        Self {
            trees: self.trees.clone(),
            // Don't clone the cache, just create a new empty one
            cache: StorageCache::default(),
        }
    }
}

impl<C: Hash + Eq> Snapshot<C> {
    pub fn new(cache: StorageCache) -> Self {
        Self {
            trees: HashMap::new(),
            cache,
        }
    }

    /// Remove a key from our snapshot
    pub fn delete<K: Into<Bytes>>(&mut self, column: C, key: K) -> EntryState<Bytes> {
        self.trees.entry(column)
            .or_insert_with(Changes::default)
            .remove(key)
    }

    /// Count entries based on our snapshot state and the provided iterator for remaining entries on disk
    pub fn count_entries<I: AsRef<[u8]>, E: StdError + Send + Sync + 'static>(&self, column: C, iterator: impl Iterator<Item = Result<(I, I), E>>) -> usize {
        let changes = self.trees.get(&column);
        iterator.map(|res| {
            let (k, _) = res?;

            let is_deleted = changes.map_or(false, |changes| changes.writes.get(k.as_ref())
                .map_or(false, |v| v.is_none())
            );

            let v = if is_deleted {
                None
            } else {
                Some(())
            };

            Ok::<_, E>(v)
        }).filter_map(Result::transpose)
        .count()
    }

    /// Check if snapshot is empty based on our snapshot state and the provided iterator for remaining entries on disk
    pub fn is_empty<I: AsRef<[u8]>, E: StdError + Send + Sync + 'static>(&self, column: C, iterator: impl Iterator<Item = Result<(I, I), E>>) -> bool {
        let changes = self.trees.get(&column);

        if let Some(batch) = changes.as_ref() {
            let any = batch.writes.iter()
                .find(|(_, v)| v.is_some());
    
            if any.is_some() {
                return true
            }
        }

        let next = iterator.map(|res| {
            let (k, _) = res?;

            let is_deleted = changes.map_or(false, |changes| changes.writes.get(k.as_ref())
                .map_or(false, |v| v.is_none())
            );

            let v = if is_deleted {
                None
            } else {
                Some(())
            };

            Ok::<_, E>(v)
        }).filter_map(Result::transpose)
        .next();

        next.is_none()
    }

    /// Returns the previous value if any
    pub fn put<K: Into<Bytes>, V: Into<Bytes>>(&mut self, column: C, key: K, value: V) -> EntryState<Bytes> {
        self.trees.entry(column)
            .or_insert_with(Changes::default)
            .insert(key, value)
    }

    /// Get a value from our snapshot
    pub fn get<'a, K: AsRef<[u8]>>(&'a self, column: C, key: K) -> EntryState<&'a Bytes> {
        match self.trees.get(&column) {
            Some(batch) => match batch.writes.get(key.as_ref()) {
                Some(Some(v)) => EntryState::Stored(v),
                Some(None) => EntryState::Deleted,
                None => EntryState::Absent,
            },
            None => EntryState::Absent,
        }
    }

    /// Get the size of a value from our snapshot
    pub fn get_size<'a, K: AsRef<[u8]>>(&'a self, column: C, key: K) -> EntryState<usize> {
        match self.trees.get(&column) {
            Some(batch) => match batch.writes.get(key.as_ref()) {
                Some(Some(v)) => EntryState::Stored(v.len()),
                Some(None) => EntryState::Deleted,
                None => EntryState::Absent,
            },
            None => EntryState::Absent,
        }
    }

    /// Check if a key is present in our snapshot
    pub fn contains<K: AsRef<[u8]>>(&self, column: C, key: K) -> Option<bool> {
        let batch = self.trees.get(&column)?;
        batch.contains(key)
    }

    /// Check if a key is present in our snapshot, defaulting to false
    pub fn contains_key<K: AsRef<[u8]>>(&self, column: C, key: K) -> bool {
        self.contains(column, key).unwrap_or(false)
    }

    // Lazy interator over raw keys and values as BytesView
    /// Note that this iterator is not allocating or copying any data from it!
    pub fn lazy_iter_raw<'a, I: AsRef<[u8]> + Into<BytesView<'a>> + 'a, E: StdError + Send + Sync + 'static>(
        &'a self,
        column: C,
        mode: IteratorMode,
        iterator: impl Iterator<Item = Result<(I, I), E>> + 'a,
    ) -> impl Iterator<Item = Result<(BytesView<'a>, BytesView<'a>), BlockchainError>> + 'a {
        match self.trees.get(&column) {
            Some(tree) => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;

                        // Snapshot doesn't contains the key,
                        // We can use the one from disk
                        let k = key.as_ref();
                        if !tree.writes.contains_key(k) {
                            let k = key.into();
                            let v = value.into();
                            Ok(Some((k, v)))
                        } else {
                            Ok(None)
                        }
                    }).filter_map(Result::transpose);

                let mem_iter: Box<dyn Iterator<Item = (BytesView<'a>, BytesView<'a>)> + Send + Sync> = match mode {
                    IteratorMode::Start => {
                        Box::new(tree.writes.iter()
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k.into(), v.into())))
                        )
                    },
                    IteratorMode::End => {
                        Box::new(tree.writes.iter()
                            .rev()
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k.into(), v.into())))
                        )
                    },
                    IteratorMode::WithPrefix(prefix, direction) => {
                        let prefix = prefix.to_vec();
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.iter()),
                            Direction::Reverse => Either::Right(tree.writes.iter().rev()),
                        };
                        Box::new(iter
                            .filter_map(move |(k, v)| {
                                if let Some(v) = v {
                                    if k.starts_with(&prefix) {
                                        return Some((k.into(), v.into()));
                                    }
                                }
                                None
                            })
                        )
                    },
                    IteratorMode::From(start, direction) => {
                        let start = Bytes::from(start.to_vec());
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.range(start..)),
                            Direction::Reverse => Either::Right(tree.writes.range(..=start).rev()),
                        };
                        Box::new(iter
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k.into(), v.into())))
                        )
                    },
                    IteratorMode::Range { lower_bound, upper_bound, direction } => {
                        let lower = Bytes::from(lower_bound.to_vec());
                        let upper = Bytes::from(upper_bound.to_vec());
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.range(lower..upper)),
                            Direction::Reverse => Either::Right(tree.writes.range(lower..upper).rev()),
                        };
                        Box::new(iter
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k.into(), v.into())))
                        )
                    },
                };

                let mem_iter = mem_iter.into_iter()
                    .map(|(k, v)| Ok((k.into(), v.into())));

                Either::Left(disk_iter.chain(mem_iter))
            },
            None => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;
                        let k = key.into();
                        let v = value.into();
                        Ok((k, v))
                    });

                Either::Right(disk_iter)
            }
        }
    }

    // Lazy interator over keys and values
    // Both are parsed from bytes
    // It will fallback on the disk iterator
    // if the key is not present in the batch
    // Note that this iterator is lazy and is
    // not allocating or copying any data from it!
    #[inline]
    pub fn lazy_iter<'a, K, V, I: AsRef<[u8]> + Into<BytesView<'a>> + 'a, E: StdError + Send + Sync + 'static>(
        &'a self,
        column: C,
        mode: IteratorMode,
        iterator: impl Iterator<Item = Result<(I, I), E>> + 'a,
    ) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
    {
        self.lazy_iter_raw::<I, E>(column, mode, iterator)
            .map(|res| {
                let (k_bytes, v_bytes) = res?;

                let k = K::from_bytes(k_bytes.as_ref())
                    .context("Failed to deserialize key in snapshot iterator")?;
                let v = V::from_bytes(v_bytes.as_ref())
                    .context("Failed to deserialize value in snapshot iterator")?;

                Ok((k, v))
            })
    }

    // Similar to `iter` but only for keys
    // Note that this iterator is lazy and is
    // not allocating or copying any data from it!
    #[inline]
    pub fn lazy_iter_keys<'a, K, I: AsRef<[u8]> + Into<BytesView<'a>> + 'a, E: StdError + Send + Sync + 'static>(
        &'a self,
        column: C,
        mode: IteratorMode,
        iterator: impl Iterator<Item = Result<(I, I), E>> + 'a,
    ) -> impl Iterator<Item = Result<K, BlockchainError>> + 'a
    where
        K: Serializer + 'a
    {
        self.lazy_iter::<K, (), I, E>(column, mode, iterator)
            .map(|res| res.map(|(k, _)| k))
    }
}