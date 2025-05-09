mod column;
mod types;
mod providers;
mod snapshot;

use anyhow::Context;
use itertools::Either;
use log::trace;
use rocksdb::{ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode, MultiThreaded, Options, SliceTransform};
use strum::IntoEnumIterator;
use xelis_common::{network::Network, serializer::Serializer};
use crate::core::error::{BlockchainError, DiskContext};

pub use column::*;
pub use types::*;

pub use snapshot::Snapshot;

macro_rules! cf_handle {
    ($self: expr, $column: expr) => {
        $self.db.cf_handle($column.as_ref())
            .with_context(|| format!("Column {:?} not found", $column))?
    };
}

pub struct RocksStorage {
    db: DBWithThreadMode<MultiThreaded>,
    network: Network,
    pub(super) snapshot: Option<Snapshot> 
}

impl RocksStorage {
    pub fn new(network: Network) -> Self {
        let cfs = Column::iter()
            .map(|column| {
                let name = column.to_string();
                let prefix = column.prefix();
                let mut opts = Options::default();
                if let Some(len) = prefix {
                    opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(len));
                }

                ColumnFamilyDescriptor::new(name, opts)
            });

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db  = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(&opts, "/rocksdb", cfs)
            .expect("Failed to open RocksDB");

        Self {
            db,
            network,
            snapshot: None
        }
    }

    pub fn load_cache_from_disk(&mut self) {
        trace!("load cache from disk");
    }

    pub(super) fn insert_into_disk<K: AsRef<[u8]>, V: Serializer>(&mut self, column: Column, key: K, value: &V) -> Result<(), BlockchainError> {
        trace!("insert into disk {:?}", column);

        match self.snapshot.as_mut() {
            Some(snapshot) => snapshot.put(column, key.as_ref().to_vec(), value.to_bytes()),
            None => {
                let cf = cf_handle!(self, column);
                self.db.put_cf(&cf, key.as_ref(), value.to_bytes())
                    .with_context(|| format!("Error while inserting into disk column {:?}", column))?
            }
        };

        Ok(())
    }

    pub(super) fn remove_from_disk<K: Serializer>(&mut self, column: Column, key: &K) -> Result<(), BlockchainError> {
        trace!("remove from disk {:?}", column);

        match self.snapshot.as_mut() {
            Some(snapshot) => snapshot.delete(column, key.to_bytes()),
            None => {
                let cf = cf_handle!(self, column);
                self.db.delete_cf(&cf, key.to_bytes())
                    .with_context(|| format!("Error while removing from disk column {:?}", column))?;
            }
        };

        Ok(())
    }

    pub fn contains_data<K: Serializer>(&self, column: Column, key: &K) -> Result<bool, BlockchainError> {
        trace!("contains data {:?}", column);

        let key_bytes = key.to_bytes();
        if let Some(snapshot) = self.snapshot.as_ref() {
            if let Some(v) = snapshot.contains(column, &key_bytes) {
                return Ok(v)
            }
        }

        let cf = cf_handle!(self, column);
        let value = self.db.get_pinned_cf(&cf, key_bytes)
            .with_context(|| format!("Error while checking if key exists in column {:?}", column))?;

        Ok(value.is_some())
    }

    // NOTE: If its used over a snapshot, we can't ensure that its fully empty
    // Because we would have to iterate over all the keys in the column
    // and check that they are all marked as deleted in snapshot
    pub fn is_empty(&self, column: Column) -> Result<bool, BlockchainError> {
        trace!("is empty {:?}", column);

        let cf = cf_handle!(self, column);
        let mut iterator = self.db.iterator_cf(&cf, IteratorMode::Start);

        Ok(iterator.next().is_none())
    }

    pub fn load_optional_from_disk<K: AsRef<[u8]> + ?Sized, V: Serializer>(&self, column: Column, key: &K) -> Result<Option<V>, BlockchainError> {
        trace!("load optional {:?} from disk internal", column);

        let cf = cf_handle!(self, column);
        match self.db.get_pinned_cf(&cf, key.as_ref())
            .with_context(|| format!("Internal error while reading column {:?}", column))? {
            Some(bytes) => Ok(Some(V::from_bytes(&bytes)?)),
            None => Ok(None)
        }
    }

    pub fn load_from_disk<K: AsRef<[u8]> + ?Sized, V: Serializer>(&self, column: Column, key: &K) -> Result<V, BlockchainError> {
        trace!("load from disk internal");

        let data = self.load_optional_from_disk(column, key)?
            .with_context(|| format!("Error while loading from {:?} with key {:?}", column, key.as_ref()))?;

        Ok(data)
    }

    pub fn get_size_from_disk<K: AsRef<[u8]>>(&self, column: Column, key: &K) -> Result<usize, BlockchainError> {
        trace!("load from disk internal");

        let cf = cf_handle!(self, column);
        match self.db.get_pinned_cf(&cf, key.as_ref())
            .with_context(|| format!("Internal error while reading {:?}", column))? {
            Some(bytes) => Ok(bytes.len()),
            None => Err(BlockchainError::NotFoundOnDisk(DiskContext::DataLen))
        }
    }

    pub fn iter_prefix<'a, K: Serializer + 'a, V: Serializer + 'a, P: AsRef<[u8]> + Copy + 'a>(&'a self, column: Column, prefix: P) -> Result<impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a, BlockchainError> {
        trace!("iter prefix {:?}", column);

        let cf = cf_handle!(self, column);
        let iterator = self.db.prefix_iterator_cf(&cf, prefix);

        match self.snapshot.as_ref() {
            Some(snapshot) => Ok(Either::Left(snapshot.iter_prefix(column, prefix, iterator))),
            None => {
                Ok(Either::Right(iterator.map(|res| {
                    let (key, value) = res.context("Internal read error in iter")?;
                    let key = K::from_bytes(&key)?;
                    let value = V::from_bytes(&value)?;
        
                    Ok((key, value))
                })))
            } 
        }
    }

    pub fn iter_keys_prefix<'a, K: Serializer + 'a, P: AsRef<[u8]> + Copy + 'a>(&'a self, column: Column, prefix: P) -> Result<impl Iterator<Item = Result<K, BlockchainError>> + 'a, BlockchainError> {
        trace!("iter keys prefix {:?}", column);

        let cf = cf_handle!(self, column);
        let iterator = self.db.prefix_iterator_cf(&cf, prefix);

        match self.snapshot.as_ref() {
            Some(snapshot) => Ok(Either::Left(snapshot.iter_keys_prefix(column, prefix, iterator))),
            None => {
                Ok(Either::Right(iterator.map(|res| {
                    let (key, _) = res.context("Internal read error in iter")?;
                    let key = K::from_bytes(&key)?;
                    Ok(key)
                })))
            } 
        }
    }

    pub fn iter<'a, K: Serializer + 'a, V: Serializer + 'a>(&'a self, column: Column) -> Result<impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a, BlockchainError> {
        trace!("iter {:?}", column);

        let cf = cf_handle!(self, column);
        let iterator = self.db.iterator_cf(&cf, IteratorMode::Start);

        match self.snapshot.as_ref() {
            Some(snapshot) => Ok(Either::Left(snapshot.iter(column, iterator))),
            None => {
                Ok(Either::Right(iterator.map(|res| {
                    let (key, value) = res.context("Internal read error in iter")?;
                    let key = K::from_bytes(&key)?;
                    let value = V::from_bytes(&value)?;
        
                    Ok((key, value))
                })))
            } 
        }
    }

    pub fn iter_keys<'a, K: Serializer + 'a>(&'a self, column: Column) -> Result<impl Iterator<Item = Result<K, BlockchainError>> + 'a, BlockchainError> {
        trace!("iter keys {:?}", column);

        let cf = cf_handle!(self, column);
        let iterator = self.db.iterator_cf(&cf, IteratorMode::Start);

        match self.snapshot.as_ref() {
            Some(snapshot) => Ok(Either::Left(snapshot.iter_keys(column, iterator))),
            None => {
                Ok(Either::Right(iterator.map(|res| {
                    let (key, _) = res.context("Internal read error in iter_keys")?;
                    let key = K::from_bytes(&key)?;
        
                    Ok(key)
                })))
            } 
        }
    }
}