mod column;
mod types;
mod providers;

use anyhow::Context;
use log::trace;
use rocksdb::{ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode, MultiThreaded, Options, SliceTransform};
use strum::IntoEnumIterator;
use xelis_common::{network::Network, serializer::Serializer};
use crate::core::error::{BlockchainError, DiskContext};

pub use column::*;
pub use types::*;

macro_rules! cf_handle {
    ($self: expr, $column: expr) => {
        $self.db.cf_handle(&$column.to_string())
            .with_context(|| format!("Column {:?} not found", $column))?
    };
}

pub struct RocksStorage {
    db: DBWithThreadMode<MultiThreaded>,
    network: Network,
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
            network
        }
    }

    pub fn load_cache_from_disk(&mut self) {
        trace!("load cache from disk");
    }

    pub(super) fn insert_into_disk<K: Serializer, V: Serializer>(&self, column: Column, key: &K, value: &V) -> Result<(), BlockchainError> {
        let cf = cf_handle!(self, column);

        self.db.put_cf(&cf, key.to_bytes(), value.to_bytes())
            .with_context(|| format!("Error while inserting into disk column {:?}", column))?;

        Ok(())
    }

    pub fn contains_data<K: Serializer>(&self, column: Column, key: &K) -> Result<bool, BlockchainError> {
        let cf = cf_handle!(self, column);

        let value = self.db.get_pinned_cf(&cf, key.to_bytes())
            .with_context(|| format!("Error while checking if key exists in column {:?}", column))?;

        Ok(value.is_some())
    }

    pub fn load_optional_from_disk<T: Serializer>(&self, column: Column, key: &[u8]) -> Result<Option<T>, BlockchainError> {
        trace!("load optional from disk internal");

        let cf = cf_handle!(self, column);
        match self.db.get_pinned_cf(&cf, key)
            .with_context(|| format!("Internal error while reading Column {:?}", column))? {
            Some(bytes) => Ok(Some(T::from_bytes(&bytes)?)),
            None => Ok(None)
        }
    }

    pub fn load_from_disk<T: Serializer>(&self, column: Column, key: &[u8], context: DiskContext) -> Result<T, BlockchainError> {
        trace!("load from disk internal");
        self.load_optional_from_disk(column, key)?
            .ok_or(BlockchainError::NotFoundOnDisk(context))
    }

    pub fn scan_prefix<'a, K: Serializer, V: Serializer>(&'a self, column: Column, prefix: &'a [u8]) -> Result<impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a, BlockchainError> {
        let cf = cf_handle!(self, column);
        let iterator = self.db.prefix_iterator_cf(&cf, prefix);

        Ok(iterator.map(|res| {
            let (key, value) = res.context("Internal read error in scan prefix")?;
            let key = K::from_bytes(&key)?;
            let value = V::from_bytes(&value)?;

            Ok((key, value))
        }))
    }

    pub fn iter<'a, K: Serializer, V: Serializer>(&'a self, column: Column) -> Result<impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a, BlockchainError> {
        let cf = cf_handle!(self, column);
        let iterator = self.db.iterator_cf(&cf, IteratorMode::Start);

        Ok(iterator.map(|res| {
            let (key, value) = res.context("Internal read error in scan prefix")?;
            let key = K::from_bytes(&key)?;
            let value = V::from_bytes(&value)?;

            Ok((key, value))
        }))
    }
}