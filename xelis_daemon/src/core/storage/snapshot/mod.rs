mod changes;
mod iterator_mode;

use std::{
    collections::HashMap,
    hash::Hash,
    error::Error as StdError,
};

use anyhow::Context;
use bytes::Bytes;
use itertools::Either;
use xelis_common::{serializer::Serializer};
use crate::core::{error::BlockchainError, storage::snapshot::changes::Changes};

pub use iterator_mode::*;

pub struct Snapshot<C: Hash + Eq> {
    pub trees: HashMap<C, Changes>,
}

impl<C: Hash + Eq> Snapshot<C> {
    pub fn new() -> Self {
        Self {
            trees: HashMap::new(),
        }
    }

    pub fn delete<K: Into<Bytes>>(&mut self, column: C, key: K) {
        self.trees.entry(column)
            .or_insert_with(Changes::default)
            .remove(key);
    }

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

    pub fn put<K: Into<Bytes>, V: Into<Bytes>>(&mut self, column: C, key: K, value: V) {
        self.trees.entry(column)
            .or_insert_with(Changes::default)
            .insert(key, value);
    }

    pub fn get<'a, K: AsRef<[u8]>>(&'a self, column: C, key: K) -> Option<Option<&'a Bytes>> {
        let batch = self.trees.get(&column)?;
        batch.writes.get(key.as_ref())
            .map(|v| v.as_ref())
    }

    pub fn get_size<'a, K: AsRef<[u8]>>(&'a self, column: C, key: K) -> Option<Option<usize>> {
        let batch = self.trees.get(&column)?;
        batch.writes.get(key.as_ref())
            .map(|v| v.as_ref().map(|v| v.len()))
    }

    pub fn contains<K: AsRef<[u8]>>(&self, column: C, key: K) -> Option<bool> {
        let batch = self.trees.get(&column)?;
        batch.contains(key)
    }

    pub fn contains_key<K: AsRef<[u8]>>(&self, column: C, key: K) -> bool {
        self.contains(column, key).unwrap_or(false)
    }

    // Lazy interator over keys and values
    // Both are parsed from bytes
    // It will fallback on the disk iterator
    // if the key is not present in the batch
    // Note that this iterator is lazy and is
    // not allocating or copying any data from it!
    pub fn lazy_iter<'a, K, V, I: AsRef<[u8]>, E: StdError + Send + Sync + 'static>(
        &'a self,
        column: C,
        mode: IteratorMode,
        iterator: impl Iterator<Item = Result<(I, I), E>> + 'a,
    ) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
    {
        match self.trees.get(&column) {
            Some(tree) => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;

                        // Snapshot doesn't contains the key,
                        // We can use the one from disk
                        if !tree.writes.contains_key(key.as_ref()) {
                            Ok(Some((K::from_bytes(key.as_ref())?, V::from_bytes(value.as_ref())?)))
                        } else {
                            Ok(None)
                        }
                    }).filter_map(Result::transpose);

                let mem_iter: Box<dyn Iterator<Item = (&'a Bytes, &'a Bytes)> + Send + Sync> = match mode {
                    IteratorMode::Start => {
                        Box::new(tree.writes.iter()
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
                        )
                    },
                    IteratorMode::End => {
                        Box::new(tree.writes.iter().rev()
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
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
                                        return Some((k, v));
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
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
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
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
                        )
                    },
                };

                let mem_iter = mem_iter.into_iter()
                    .map(|(k, v)| Ok((K::from_bytes(k)?, V::from_bytes(v)?)));

                Either::Left(disk_iter.chain(mem_iter))
            },
            None => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;
                        Ok((K::from_bytes(key.as_ref())?, V::from_bytes(value.as_ref())?))
                    });

                Either::Right(disk_iter)
            }
        }
    }

    // Similar to `iter` but only for keys
    // Note that this iterator is lazy and is
    // not allocating or copying any data from it!
    pub fn lazy_iter_keys<'a, K, I: AsRef<[u8]>, E: StdError + Send + Sync + 'static>(
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

    // Iterator over keys and values
    // Both are parsed from bytes
    // It will fallback on the disk iterator
    // if the key is not present in the batch
    // NOTE: this iterator will copy and allocate
    // the data from the iterators to prevent borrowing
    // current snapshot.
    pub fn iter_owned<'a, K, V, I: AsRef<[u8]>, E: StdError + Send + Sync + 'static>(
        &self,
        column: C,
        mode: IteratorMode,
        iterator: impl Iterator<Item = Result<(I, I), E>> + 'a,
    ) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
    {
        match self.trees.get(&column) {
            Some(tree) => {
                let disk_iter = iterator
                    .map(|res| {
                        let (key, value) = res.context("Internal error in snapshot iterator")?;

                        // Snapshot doesn't contain the key,
                        // so we can use the one from disk
                        if !tree.writes.contains_key(key.as_ref()) {
                            Ok(Some((K::from_bytes(key.as_ref())?, V::from_bytes(value.as_ref())?)))
                        } else {
                            Ok(None)
                        }
                    })
                    .filter_map(Result::transpose);

                let mem_iter: Box<dyn Iterator<Item = (&Bytes, &Bytes)> + Send + Sync> = match mode {
                    IteratorMode::Start => {
                        Box::new(tree.writes.iter()
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))
                    }
                    IteratorMode::End => {
                        Box::new(tree.writes.iter().rev()
                            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))
                    }
                    IteratorMode::WithPrefix(prefix, direction) => {
                        let prefix = prefix.to_vec();
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.iter()),
                            Direction::Reverse => Either::Right(tree.writes.iter().rev()),
                        };
                        Box::new(iter.filter_map(move |(k, v)| {
                            if let Some(v) = v {
                                if k.starts_with(&prefix) {
                                    return Some((k, v));
                                }
                            }
                            None
                        }))
                    }
                    IteratorMode::From(start, direction) => {
                        let start = Bytes::from(start.to_vec());
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.range(start..)),
                            Direction::Reverse => Either::Right(tree.writes.range(..=start).rev()),
                        };
                        Box::new(iter.filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))
                    }
                    IteratorMode::Range {
                        lower_bound,
                        upper_bound,
                        direction,
                    } => {
                        let lower = Bytes::from(lower_bound.to_vec());
                        let upper = Bytes::from(upper_bound.to_vec());
                        let iter = match direction {
                            Direction::Forward => Either::Left(tree.writes.range(lower..upper)),
                            Direction::Reverse => Either::Right(tree.writes.range(lower..upper).rev()),
                        };
                        Box::new(iter.filter_map(|(k, v)| v.as_ref().map(|v| (k, v))))
                    }
                };

                let mem_iter = mem_iter.into_iter()
                    .map(|(k, v)| Ok((K::from_bytes(k)?, V::from_bytes(v)?)));

                Either::Left(disk_iter.chain(mem_iter).collect::<Vec<_>>().into_iter())
            }
            None => {
                let disk_iter = iterator.map(|res| {
                    let (key, value) = res.context("Internal error in snapshot iterator")?;
                    Ok((K::from_bytes(key.as_ref())?, V::from_bytes(value.as_ref())?))
                });

                Either::Right(disk_iter)
            }
        }
    }
}