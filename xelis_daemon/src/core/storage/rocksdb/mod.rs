mod column;
mod types;
mod providers;
mod snapshot;

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use itertools::Either;
use log::{debug, trace};
use rocksdb::{
    ColumnFamilyDescriptor,
    DBCompactionStyle,
    DBWithThreadMode,
    Direction,
    Env,
    IteratorMode as InternalIteratorMode,
    MultiThreaded,
    Options,
    ReadOptions,
    SliceTransform,
    WaitForCompactOptions
};
use strum::IntoEnumIterator;
use xelis_common::{
    block::{BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable,
    network::Network,
    serializer::{Count, Serializer},
    tokio,
    transaction::Transaction,
    utils::detect_available_parallelism
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{BlocksAtHeightProvider, ClientProtocolProvider, ContractOutputsProvider, Tips}
};

pub use column::*;
pub use types::*;

pub use snapshot::Snapshot;

use super::Storage;

macro_rules! cf_handle {
    ($db: expr, $column: expr) => {
        $db.cf_handle($column.as_ref())
            .with_context(|| format!("Column {:?} not found", $column))?
    };
}

type InnerDB = DBWithThreadMode<MultiThreaded>;

#[derive(Copy, Clone)]
pub enum IteratorMode<'a> {
    Start,
    End,
    // Allow for range start operations
    From(&'a [u8], Direction),
    // Strict prefix to all keys
    WithPrefix(&'a [u8], Direction),
}

impl<'a> IteratorMode<'a> {
    pub fn convert(self) -> (InternalIteratorMode<'a>, ReadOptions) {
        let mut opts = ReadOptions::default();
        let mode = match self {
            Self::Start => InternalIteratorMode::Start,
            Self::End => InternalIteratorMode::End,
            Self::From(prefix, direction) => InternalIteratorMode::From(prefix, direction),
            Self::WithPrefix(prefix, direction) => {
                opts.set_prefix_same_as_start(true);
                InternalIteratorMode::From(prefix, direction)
            }
        };

        (mode, opts)
    }
}

pub struct RocksStorage {
    db: Arc<InnerDB>,
    network: Network,
    snapshot: Option<Snapshot> 
}

impl RocksStorage {
    pub fn new(dir: &str, network: Network) -> Self {
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
        opts.set_compaction_style(DBCompactionStyle::Universal);

        // TODO: expose these config
        let cores = detect_available_parallelism();
        opts.increase_parallelism(cores as _);
        opts.set_max_background_jobs(cores as _);
        opts.set_max_subcompactions(cores as _);

        opts.set_max_open_files(1024);
        opts.set_keep_log_file_num(4);

        let mut env = Env::new().expect("Creating new env");
        env.set_low_priority_background_threads(cores  as _);
        opts.set_env(&env);

        let db  = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(&opts, format!("{}{}", dir, network.to_string().to_lowercase()), cfs)
            .expect("Failed to open RocksDB");

        Self {
            db: Arc::new(db),
            network,
            snapshot: None
        }
    }

    pub fn load_cache_from_disk(&mut self) {
        trace!("load cache from disk");
    }

    pub(super) fn insert_into_disk<K: AsRef<[u8]>, V: Serializer>(&mut self, column: Column, key: K, value: &V) -> Result<(), BlockchainError> {
        Self::insert_into_disk_internal(&self.db, self.snapshot.as_mut(), column, key, value)
    }

    pub(super) fn remove_from_disk<K: Serializer>(&mut self, column: Column, key: &K) -> Result<(), BlockchainError> {
        Self::remove_from_disk_internal(&self.db, self.snapshot.as_mut(), column, key)
    }

    pub fn contains_data<K: AsRef<[u8]>>(&self, column: Column, key: &K) -> Result<bool, BlockchainError> {
        trace!("contains data {:?}", column);

        let key_bytes = key.as_ref();
        if let Some(snapshot) = self.snapshot.as_ref() {
            if let Some(v) = snapshot.contains(column, &key_bytes) {
                return Ok(v)
            }
        }

        let cf = cf_handle!(self.db, column);
        let value = self.db.get_pinned_cf(&cf, key_bytes)
            .with_context(|| format!("Error while checking if key exists in column {:?}", column))?;

        Ok(value.is_some())
    }

    // NOTE: If its used over a snapshot, we can't ensure that its fully empty
    // Because we would have to iterate over all the keys in the column
    // and check that they are all marked as deleted in snapshot
    pub fn is_empty(&self, column: Column) -> Result<bool, BlockchainError> {
        trace!("is empty {:?}", column);

        let cf = cf_handle!(self.db, column);
        let mut iterator = self.db.iterator_cf(&cf, InternalIteratorMode::Start);
        Ok(iterator.next().is_none())
    }

    pub fn load_optional_from_disk<K: AsRef<[u8]> + ?Sized, V: Serializer>(&self, column: Column, key: &K) -> Result<Option<V>, BlockchainError> {
        trace!("load optional {:?} from disk internal", column);

        let cf = cf_handle!(self.db, column);
        match self.db.get_pinned_cf(&cf, key.as_ref())
            .with_context(|| format!("Internal error while reading column {:?}", column))? {
            Some(bytes) => Ok(Some(V::from_bytes(&bytes)?)),
            None => Ok(None)
        }
    }

    pub fn load_from_disk<K: AsRef<[u8]> + ?Sized, V: Serializer>(&self, column: Column, key: &K) -> Result<V, BlockchainError> {
        trace!("load from disk internal {:?}", column);

        self.load_optional_from_disk(column, key)?
            .ok_or(BlockchainError::NotFoundOnDisk(DiskContext::LoadData))
    }

    pub fn get_size_from_disk<K: AsRef<[u8]>>(&self, column: Column, key: &K) -> Result<usize, BlockchainError> {
        trace!("load from disk internal {:?}", column);

        if let Some(v) = self.snapshot.as_ref().and_then(|s| s.get_size(column, key.as_ref())) {
            match v {
                Some(v) => return Ok(v),
                None => return Err(BlockchainError::NotFoundOnDisk(DiskContext::DataLen))
            }
        }

        let cf = cf_handle!(self.db, column);
        match self.db.get_pinned_cf(&cf, key.as_ref())
            .with_context(|| format!("Internal error while reading {:?}", column))? {
            Some(bytes) => Ok(bytes.len()),
            None => Err(BlockchainError::NotFoundOnDisk(DiskContext::DataLen))
        }
    }

    // Internal functions for better borrow checking

    pub fn load_optional_from_disk_internal<K: AsRef<[u8]> + ?Sized, V: Serializer>(db: &InnerDB, snapshot: Option<&Snapshot>, column: Column, key: &K) -> Result<Option<V>, BlockchainError> {
        trace!("load optional {:?} from disk internal", column);

        if let Some(v) = snapshot.and_then(|s| s.get(column, key.as_ref())) {
            match v {
                Some(v) => return Ok(Some(V::from_bytes(&v)?)),
                None => return Ok(None)
            }
        }

        let cf = cf_handle!(db, column);
        match db.get_pinned_cf(&cf, key.as_ref())
            .with_context(|| format!("Internal error while reading column {:?}", column))? {
            Some(bytes) => Ok(Some(V::from_bytes(&bytes)?)),
            None => Ok(None)
        }
    }

    pub(super) fn insert_into_disk_internal<K: AsRef<[u8]>, V: Serializer>(db: &InnerDB, snapshot: Option<&mut Snapshot>, column: Column, key: K, value: &V) -> Result<(), BlockchainError> {
        trace!("insert into disk {:?}", column);

        match snapshot {
            Some(snapshot) => snapshot.put(column, key.as_ref().to_vec(), value.to_bytes()),
            None => {
                let cf = cf_handle!(db, column);
                db.put_cf(&cf, key.as_ref(), value.to_bytes())
                    .with_context(|| format!("Error while inserting into disk column {:?}", column))?
            }
        };

        Ok(())
    }

    pub(super) fn remove_from_disk_internal<K: Serializer>(db: &InnerDB, snapshot: Option<&mut Snapshot>, column: Column, key: &K) -> Result<(), BlockchainError> {
        trace!("remove from disk {:?}", column);

        match snapshot {
            Some(snapshot) => snapshot.delete(column, key.to_bytes()),
            None => {
                let cf = cf_handle!(db, column);
                db.delete_cf(&cf, key.to_bytes())
                    .with_context(|| format!("Error while removing from disk column {:?}", column))?;
            }
        };

        Ok(())
    }

    pub fn iter_owned_internal<'a, K, V>(db: &'a InnerDB, snapshot: Option<&Snapshot>, mode: IteratorMode, column: Column) -> Result<impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a, BlockchainError>
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
    {
        trace!("iter owned {:?}", column);

        let cf = cf_handle!(db, column);
        let (m, opts) = mode.convert();
        let iterator = db.iterator_cf_opt(&cf, opts, m);

        match snapshot {
            Some(snapshot) => Ok(Either::Left(snapshot.iter_owned(column, mode, iterator))),
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

    pub fn iter_internal<'a, K, V>(db: &'a InnerDB, snapshot: Option<&'a Snapshot>, mode: IteratorMode, column: Column) -> Result<impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a, BlockchainError>
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
    {
        trace!("iter {:?}", column);

        let cf = cf_handle!(db, column);
        let (m, opts) = mode.convert();
        let iterator = db.iterator_cf_opt(&cf, opts, m);

        match snapshot {
            Some(snapshot) => Ok(Either::Left(snapshot.lazy_iter(column, mode, iterator))),
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

    pub fn iter_keys_internal<'a, K>(db: &'a InnerDB, snapshot: Option<&'a Snapshot>, mode: IteratorMode, column: Column) -> Result<impl Iterator<Item = Result<K, BlockchainError>> + 'a, BlockchainError>
    where
        K: Serializer + 'a,
    {
        trace!("iter keys {:?}", column);

        let cf = cf_handle!(db, column);
        let (m, opts) = mode.convert();
        let iterator = db.iterator_cf_opt(&cf, opts, m);

        match snapshot {
            Some(snapshot) => Ok(Either::Left(snapshot.lazy_iter_keys(column, mode, iterator))),
            None => {
                Ok(Either::Right(iterator.map(|res| {
                    let (key, _) = res.context("Internal read error in iter_keys")?;
                    let key = K::from_bytes(&key)?;
        
                    Ok(key)
                })))
            } 
        }
    }

    #[inline(always)]
    pub fn iter<'a, K, V>(&'a self, column: Column, mode: IteratorMode) -> Result<impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a, BlockchainError>
    where
        K: Serializer + 'a,
        V: Serializer + 'a,
    {
        Self::iter_internal(&self.db, self.snapshot.as_ref(), mode, column)
    }

    #[inline(always)]
    pub fn iter_keys<'a, K>(&'a self, column: Column, mode: IteratorMode) -> Result<impl Iterator<Item = Result<K, BlockchainError>> + 'a, BlockchainError>
    where
        K: Serializer + 'a,
    {
        Self::iter_keys_internal(&self.db, self.snapshot.as_ref(), mode, column)
    }
}

#[async_trait]
impl Storage for RocksStorage {
    // delete block at topoheight, and all its data related
    async fn delete_block_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(Hash, Immutable<BlockHeader>, Vec<(Hash, Immutable<Transaction>)>), BlockchainError> {
        trace!("Delete block at topoheight {topoheight}");

        // delete topoheight<->hash pointers
        let hash: Hash = self.load_from_disk(Column::HashAtTopo, &topoheight.to_be_bytes())?;
        self.remove_from_disk(Column::HashAtTopo, &topoheight.to_be_bytes())?;

        trace!("deleting block execution order");
        self.remove_from_disk(Column::BlocksExecutionOrder, hash.as_bytes())?;

        trace!("hash is {hash} at topo {topoheight}");
        self.remove_from_disk(Column::TopoByHash, &hash)?;

        trace!("deleting block header {}", hash);
        let block: Immutable<BlockHeader> = self.load_from_disk(Column::Blocks, &hash)?;
        self.remove_from_disk(Column::Blocks, &hash)?;
        trace!("block header deleted successfully");

        trace!("deleting topoheight metadata");
        self.remove_from_disk(Column::TopoHeightMetadata, &topoheight.to_be_bytes())?;
        trace!("topoheight metadata deleted");

        trace!("deleting block difficulty");
        self.remove_from_disk(Column::BlockDifficulty, &hash)?;
        trace!("block deleted");

        let mut txs = Vec::with_capacity(block.get_txs_count());
        for tx_hash in block.get_transactions() {
            // Should we delete the tx too or only unlink it
            let mut should_delete = true;
            if self.has_tx_blocks(tx_hash)? {
                let mut blocks: Tips = self.load_from_disk(Column::TransactionInBlocks, tx_hash)?;
                self.remove_from_disk(Column::TransactionInBlocks, tx_hash)?;

                let blocks_len =  blocks.len();
                blocks.remove(&hash);
                should_delete = blocks.is_empty();

                if !should_delete {
                    self.set_blocks_for_tx(tx_hash, &blocks)?;
                }

                trace!("Tx was included in {} blocks, now: {}", blocks_len, blocks.len());
            }

            if self.is_tx_executed_in_block(tx_hash, &hash)? {
                trace!("Tx {} was executed in block {}, deleting", topoheight, tx_hash);
                self.unmark_tx_from_executed(&tx_hash)?;
                self.delete_contract_outputs_for_tx(&tx_hash).await?;
            }

            // We have to check first as we may have already deleted it because of client protocol
            // which allow multiple time the same txs in differents blocks
            if should_delete && self.contains_data(Column::TransactionsExecuted, tx_hash)? {
                trace!("Deleting TX {} in block {}", tx_hash, hash);
                let tx: Immutable<Transaction> = self.load_from_disk(Column::Transactions, tx_hash)?;
                self.remove_from_disk(Column::Transactions, tx_hash)?;

                txs.push((tx_hash.clone(), tx));
            }
        }

        // remove the block hash from the set, and delete the set if empty
        if self.has_blocks_at_height(block.get_height()).await? {
            self.remove_block_hash_at_height(&hash, block.get_height()).await?;
        }

        Ok((hash, block, txs))
    }

    // Get the size of the chain on disk in bytes
    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || {
            let mut size = 0;
            for column in Column::iter() {
                let cf = cf_handle!(db, column);
                let metadata = db.get_column_family_metadata_cf(&cf);
                size += metadata.size;
            }

            Ok::<_, BlockchainError>(size)
        }).await.context("Getting size on disk")?
    }

    // Estimate the size of the DB in bytes
    async fn estimate_size(&self) -> Result<u64, BlockchainError> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || {
            let mut size = 0;
            for column in Column::iter() {
                for res in Self::iter_internal::<Count, Count>(&db, None, IteratorMode::Start, column)? {
                    let (key, value) = res?;
                    size += (key.0 + value.0) as u64;
                }
            }

            Ok::<_, BlockchainError>(size)
        }).await.context("Estimating size")?
    }

    // Stop the storage and wait for it to finish
    async fn stop(&mut self) -> Result<(), BlockchainError> {
        self.flush().await
    }

    // Flush the inner DB after a block being written
    async fn flush(&mut self) -> Result<(), BlockchainError> {
        trace!("flush DB");

        let db = Arc::clone(&self.db);
        // To prevent starving the current async worker,
        // We execute the following on a blocking thread
        // and simply await its result 
        tokio::task::spawn_blocking(move || {
            for column in Column::iter() {
                debug!("compacting column {:?}", column);
                let cf = cf_handle!(db, column);
                db.compact_range_cf::<&[u8], &[u8]>(&cf, None, None);
            }
    
            debug!("wait for compact");
            let options = WaitForCompactOptions::default();
            db.wait_for_compact(&options)
                .context("Error while waiting on compact")?;
    
            debug!("flushing DB");
            db.flush()
                .context("Error while flushing DB")?;

            Ok::<_, BlockchainError>(())
        }).await.context("Flushing DB")?
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rocksdb::{Direction, IteratorMode, Options, SliceTransform, DB};
    use tempdir::TempDir;

    #[test]
    fn test_prefix_iteration_behavior() {
        // Create a temporary RocksDB instance
        let tmp_dir = TempDir::new("rocksdb-iterator").unwrap();
   
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(8));

        let db = DB::open(&opts, tmp_dir.path()).unwrap();
    
        // Helper to encode a u64 prefix + suffix
        fn make_key(prefix: u64, suffix: &[u8]) -> Vec<u8> {
            let mut key = prefix.to_be_bytes().to_vec();
            key.extend_from_slice(suffix);
            key
        }
    
        // Insert three test entries
        db.put(make_key(0, b"zero"), b"value0").unwrap();
        db.put(make_key(1, b"aaaa"), b"value1").unwrap();
        db.put(make_key(2, b"bbbb"), b"value2").unwrap();
    
        // Create an iterator starting from 1u64.to_be_bytes()
        let prefix = 1u64.to_be_bytes();

        // First test: iterator on range
        {
            let iter = db.iterator(IteratorMode::From(&prefix, Direction::Forward));
        
            // Collect matching keys for inspection
            let results: Vec<(Vec<u8>, Vec<u8>)> = iter.filter_map_ok(|(k, v)|Some((k.to_vec(), v.to_vec())))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        
            // Extract prefixes for checking
            let prefixes: Vec<u64> = results.iter()
                .map(|(k, _)| {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&k[..8]);
                    u64::from_be_bytes(buf)
                })
                .collect();
        
            // We expect keys with prefix 1 and 2
            assert_eq!(prefixes, vec![1, 2]);
            assert_eq!(results[0].1, b"value1");
            assert_eq!(results[1].1, b"value2");
        }

        // Second test: iterator on prefix only
        // First test: iterator on range
        {
            let iter = db.prefix_iterator(prefix);
        
            // Collect matching keys for inspection
            let results: Vec<(Vec<u8>, Vec<u8>)> = iter.filter_map_ok(|(k, v)|Some((k.to_vec(), v.to_vec())))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        
            // Extract prefixes for checking
            let prefixes: Vec<u64> = results.iter()
                .map(|(k, _)| {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&k[..8]);
                    u64::from_be_bytes(buf)
                })
                .collect();
        
            // We expect keys with prefix 1 only
            assert_eq!(prefixes, vec![1]);
            assert_eq!(results[0].1, b"value1");
        }
    }
}