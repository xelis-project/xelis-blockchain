mod migrations;
mod providers;

use anyhow::Context;
use async_trait::async_trait;
use itertools::Either;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::snapshot::BytesView
};
use xelis_common::{
    block::BlockHeader,
    crypto::Hash,
    immutable::Immutable,
    network::Network,
    serializer::Serializer,
    transaction::Transaction,
    tokio::sync::Mutex
};
use std::{
    hash::Hash as StdHash,
    ops::Deref,
    str::FromStr,
    sync::Arc
};
use serde::{Deserialize, Serialize};
use lru::LruCache;
use sled::{IVec, Tree};
use log::{debug, trace, info, error};

use super::{
    cache::StorageCache,
    providers::*,
    Storage,
    snapshot::{
        Snapshot as InternalSnapshot,
        EntryState,
        Direction,
        IteratorMode
    },
    Tips
};

#[derive(Clone)]
pub struct TreeWrapper(pub Tree);

impl From<&Tree> for TreeWrapper {
    fn from(tree: &Tree) -> Self {
        Self(tree.clone())
    }
}

impl Deref for TreeWrapper {
    type Target = Tree;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::hash::Hash for TreeWrapper {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.name().hash(state);
    }
}

impl std::cmp::PartialEq for TreeWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}

impl std::cmp::Eq for TreeWrapper {}


pub type Snapshot = InternalSnapshot<TreeWrapper>;

// Constant keys used for extra Tree
pub(super) const TIPS: &[u8; 4] = b"TIPS";
pub(super) const TOP_TOPO_HEIGHT: &[u8; 4] = b"TOPO";
pub(super) const TOP_HEIGHT: &[u8; 4] = b"TOPH";
pub(super) const NETWORK: &[u8; 3] = b"NET";
pub(super) const PRUNED_TOPOHEIGHT: &[u8; 4] = b"PRUN";
// Counters (prevent to perform a O(n))
pub(super) const ACCOUNTS_COUNT: &[u8; 4] = b"CACC";
pub(super) const TXS_COUNT: &[u8; 4] = b"CTXS";
pub(super) const ASSETS_COUNT: &[u8; 4] = b"CAST";
pub(super) const BLOCKS_COUNT: &[u8; 4] = b"CBLK";
pub(super) const BLOCKS_EXECUTION_ORDER_COUNT: &[u8; 4] = b"EBLK";
pub(super) const CONTRACTS_COUNT: &[u8; 4] = b"CCON";
pub(super) const DB_VERSION: &[u8; 4] = b"VRSN";

pub struct SledStorage {
    // Async operations allowed concurrency
    concurrency: usize,
    // Network used by the storage
    pub(super) network: Network,
    // All trees used to store data
    // all txs stored on disk
    pub(super) transactions: Tree,
    // all txs executed in block
    pub(super) txs_executed: Tree,
    // all blocks execution order
    pub(super) blocks_execution_order: Tree,
    // all blocks on disk
    pub(super) blocks: Tree,
    // all blocks height at specific height
    pub(super) blocks_at_height: Tree,
    // all extra data saved on disk
    pub(super) extra: Tree,
    // topo at hash on disk
    pub(super) topo_by_hash: Tree,
    // hash at topo height on disk
    pub(super) hash_at_topo: Tree,
    // mergeset data for each block hash on disk
    pub(super) mergeset: Tree,
    // cumulative difficulty for each block hash on disk
    pub(super) cumulative_difficulty: Tree,
    // Difficulty estimated covariance (P)
    pub(super) difficulty_covariance: Tree,
    // Block size ema
    pub(super) block_size_ema: Tree,
    // keep tracks of all available assets on network
    // Key is the asset hash, value is the topoheight
    pub(super) assets: Tree,
    // Key is prefixed by the topoheight for easier deletion
    // Value is the asset data
    pub(super) versioned_assets: Tree,
    // account nonces to prevent TX replay attack
    pub(super) nonces: Tree,
    // block reward for each block topoheight
    pub(super) topoheight_metadata: Tree,
    // Supply tracked for each asset
    // This tree store the latest topoheight pointer
    // asset->topoheight
    pub(super) assets_supply: Tree,
    // Versioned assets supply
    // Key is topoheight+asset->Versioned supply
    pub(super) versioned_assets_supply: Tree,
    // difficulty for each block hash
    pub(super) difficulty: Tree,
    // tree to store all blocks hashes where a tx was included in 
    pub(super) tx_blocks: Tree,
    // Tree that store all versioned nonces using hashed keys
    pub(super) versioned_nonces: Tree,
    // Tree that store all balances with prefixed keys
    pub(super) balances: Tree,

    // Tree that store all multisig setups for each account
    // Value is the topoheight pointer at the versioned multisig
    // Key is the account public key
    pub(super) multisig: Tree,
    // Tree that store all versioned multisig setups
    pub(super) versioned_multisigs: Tree,

    // Tree that store all versioned balances using hashed keys
    pub(super) versioned_balances: Tree,
    // Tree that store all merkle hashes for each topoheight
    pub(super) merkle_hashes: Tree,
    // Account registrations topoheight
    pub(super) registrations: Tree,
    // Account registrations prefixed by their topoheight for easier deletion
    pub(super) registrations_prefixed: Tree,
    // All contracts registered on the network
    // To allow up-dateable contracts, we need to version them
    // key is the hash, value is the latest topoheight
    pub(super) contracts: Tree,
    // All the versioned contracts
    // Because a contract module can be updated (or deleted), we need to keep track of all versions
    pub(super) versioned_contracts: Tree,
    // All the contracts data
    // key is composed of the contract hash and the storage key, value is the latest contract data topoheight
    pub(super) contracts_data: Tree,
    // Key is prefixed by the topoheight for fast scan_prefix search,
    // value is the contract data
    pub(super) versioned_contracts_data: Tree,
    // Key is the contract hash, value is the topoheight
    pub(super) contracts_balances: Tree,
    // Key is prefxied by the topoheight for fast scan_prefix search
    // value is the contract balance (u64)
    pub(super) versioned_contracts_balances: Tree,
    // Contract outputs per TX
    // Key is the TX Hash that called the contract, value is a list of contract outputs
    pub(super) contracts_logs: Tree,
    // Tree in {execution_topoheight}{contract} format for scheduled executions
    pub(super) contracts_scheduled_executions: Tree,
    // Tree in {topoheight}{contract}{execution_topoheight} => [empty]
    pub(super) contracts_scheduled_executions_registrations: Tree,
    // Event callbacks: {contract}{event_id}{listener_contract} => topoheight
    pub(super) contracts_event_callbacks: Tree,
    // Versioned Event callbacks: {topoheight}{contract}{event_id}{listener_contract} => VersionedEventCallback
    pub(super) versioned_contracts_event_callbacks: Tree,
    // Transactions per contract
    // {contract_hash}{tx_hash} => [empty]
    pub(super) contracts_transactions: Tree,

    // opened DB used for assets to create dynamic assets
    pub(super) db: sled::Db,

    // Cache
    pub(super) cache: StorageCache,

    // If we have a snapshot, we can use it to rollback
    pub(super) snapshot: Option<Snapshot>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    HighThroughput,
    LowSpace
}

impl Default for StorageMode {
    fn default() -> Self {
        Self::LowSpace
    }
}

impl FromStr for StorageMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "high_throughput" => Self::HighThroughput,
            "low_space" => Self::LowSpace,
            _ => return Err("Invalid storage mode".into())
        })
    }
}

impl Into<sled::Mode> for StorageMode {
    fn into(self) -> sled::Mode {
        match self {
            Self::HighThroughput => sled::Mode::HighThroughput,
            Self::LowSpace => sled::Mode::LowSpace
        }
    }
}

impl SledStorage {
    pub fn new(dir_path: String, cache_size: Option<usize>, network: Network, internal_cache_size: u64, mode: StorageMode, concurrency: usize) -> Result<Self, BlockchainError> {
        let path = format!("{}{}", dir_path, network.to_string().to_lowercase());
        let config = sled::Config::new()
            .temporary(false)
            .path(path)
            .cache_capacity(internal_cache_size)
            .mode(mode.into());

        let sled = config.open()
            .context("Failed to open sled database")?;

        fn open_tree(sled: &sled::Db, name: &str) -> Result<Tree, anyhow::Error> {
            sled.open_tree(name)
                .with_context(|| format!("Failed to open sled tree {}", name))
        }

        let mut storage = Self {
            concurrency,
            network,
            transactions: open_tree(&sled, "transactions")?,
            txs_executed: open_tree(&sled, "txs_executed")?,
            blocks_execution_order: open_tree(&sled, "blocks_execution_order")?,
            blocks: open_tree(&sled, "blocks")?,
            blocks_at_height: open_tree(&sled, "blocks_at_height")?,
            extra: open_tree(&sled, "extra")?,
            topo_by_hash: open_tree(&sled, "topo_at_hash")?,
            hash_at_topo: open_tree(&sled, "hash_at_topo")?,
            mergeset: open_tree(&sled, "mergeset")?,
            cumulative_difficulty: open_tree(&sled, "cumulative_difficulty")?,
            difficulty_covariance: open_tree(&sled, "difficulty_covariance")?,
            block_size_ema: open_tree(&sled, "block_size_ema")?,
            assets: open_tree(&sled, "assets")?,
            versioned_assets: open_tree(&sled, "versioned_assets")?,
            nonces: open_tree(&sled, "nonces")?,
            topoheight_metadata: open_tree(&sled, "topoheight_metadata")?,
            difficulty: open_tree(&sled, "difficulty")?,
            tx_blocks: open_tree(&sled, "tx_blocks")?,
            versioned_nonces: open_tree(&sled, "versioned_nonces")?,
            balances: open_tree(&sled, "balances")?,
            multisig: open_tree(&sled, "multisig")?,
            versioned_multisigs: open_tree(&sled, "versioned_multisig")?,
            versioned_balances: open_tree(&sled, "versioned_balances")?,
            merkle_hashes: open_tree(&sled, "merkle_hashes")?,
            registrations: open_tree(&sled, "registrations")?,
            registrations_prefixed: open_tree(&sled, "registrations_prefixed")?,
            contracts: open_tree(&sled, "contracts")?,
            versioned_contracts: open_tree(&sled, "versioned_contracts")?,
            contracts_data: open_tree(&sled, "contracts_data")?,
            versioned_contracts_data: open_tree(&sled, "versioned_contracts_data")?,
            contracts_balances: open_tree(&sled, "contracts_balances")?,
            versioned_contracts_balances: open_tree(&sled, "versioned_contracts_balances")?,
            contracts_logs: open_tree(&sled, "contracts_logs")?,
            contracts_scheduled_executions: open_tree(&sled, "contracts_scheduled_executions")?,
            contracts_scheduled_executions_registrations: open_tree(&sled, "contracts_scheduled_executions_registrations")?,
            assets_supply: open_tree(&sled, "assets_supply")?,
            contracts_event_callbacks: open_tree(&sled, "contracts_event_callbacks")?,
            versioned_contracts_event_callbacks: open_tree(&sled, "versioned_contracts_event_callbacks")?,
            versioned_assets_supply: open_tree(&sled, "versioned_assets_supply")?,
            contracts_transactions: open_tree(&sled, "contracts_transactions")?,
            db: sled,
            cache: StorageCache::new(cache_size),
            snapshot: None,
        };

        // Verify that we are opening a DB on same network
        // This prevent any corruption made by user
        if storage.has_network()? {
            let storage_network = storage.load_from_disk::<Network, _>(&storage.extra, NETWORK, DiskContext::Network)?;
            if storage_network != network {
                return Err(BlockchainError::InvalidNetwork);
            }
        } else {
            storage.set_network(&network)?;
        }

        if let Err(e) = storage.handle_migrations() {
            error!("Error while migrating database: {}", e);
        }

        storage.load_cache_from_disk()?;

        Ok(storage)
    }

    pub fn cache_mut(&mut self) -> &mut StorageCache {
        match self.snapshot.as_mut() {
            Some(snapshot) => &mut snapshot.cache,
            None => &mut self.cache
        }
    }

    pub fn cache(&self) -> &StorageCache {
        match self.snapshot.as_ref() {
            Some(snapshot) => &snapshot.cache,
            None => &self.cache
        }
    }

    // Load all the needed cache and counters in memory from disk 
    pub fn load_cache_from_disk(&mut self) -> Result<(), BlockchainError> {
        // Load tips from disk if available
        if let Some(tips) = self.load_optional_from_disk::<Tips, _>(&self.extra, TIPS)? {
            debug!("Found tips: {}", tips.len());
            self.cache.chain.tips = tips;
        }

        // Load the pruned topoheight from disk if available
        if let Some(pruned_topoheight) = self.load_optional_from_disk::<u64, _>(&self.extra, PRUNED_TOPOHEIGHT)? {
            debug!("Found pruned topoheight: {}", pruned_topoheight);
            self.cache.chain.pruned_topoheight = Some(pruned_topoheight);
        }

        // Load the assets count from disk if available
        if let Some(assets_count) = self.load_optional_from_disk::<u64, _>(&self.extra, ASSETS_COUNT)? {
            debug!("Found assets count: {}", assets_count);
            self.cache.assets_count = assets_count;
        }

        // Load the txs count from disk if available
        if let Some(txs_count) = self.load_optional_from_disk::<u64, _>(&self.extra, TXS_COUNT)? {
            debug!("Found txs count: {}", txs_count);
            self.cache.transactions_count = txs_count;
        }

        // Load the blocks count from disk if available
        if let Some(blocks_count) = self.load_optional_from_disk::<u64, _>(&self.extra, BLOCKS_COUNT)? {
            debug!("Found blocks count: {}", blocks_count);
            self.cache.blocks_count = blocks_count;
        }

        // Load the accounts count from disk if available
        if let Some(accounts_count) = self.load_optional_from_disk::<u64, _>(&self.extra, ACCOUNTS_COUNT)? {
            debug!("Found accounts count: {}", accounts_count);
            self.cache.accounts_count = accounts_count;
        }

        // Load the blocks execution count from disk if available
        if let Some(blocks_execution_count) = self.load_optional_from_disk::<u64, _>(&self.extra, BLOCKS_EXECUTION_ORDER_COUNT)? {
            debug!("Found blocks execution count: {}", blocks_execution_count);
            self.cache.blocks_execution_count = blocks_execution_count;
        }

        // Load the contracts count from disk if available
        if let Some(contracts_count) = self.load_optional_from_disk::<u64, _>(&self.extra, CONTRACTS_COUNT)? {
            debug!("Found contracts count: {}", contracts_count);
            self.cache.contracts_count = contracts_count;
        }

        Ok(())
    }

    pub fn load_optional_from_disk_internal<T: Serializer, K: AsRef<[u8]>>(snapshot: Option<&Snapshot>, tree: &Tree, key: K) -> Result<Option<T>, BlockchainError> {
        trace!("load optional from disk internal");
        let key_ref = key.as_ref();
        if let Some(v) = snapshot.map(|s| s.get(tree.into(), key_ref)) {
            trace!("loaded from snapshot key {:?} from db", key_ref);
            match v {
                EntryState::Stored(v) => return Ok(Some(T::from_bytes(&v)?)),
                EntryState::Deleted => return Ok(None),
                EntryState::Absent => {}
            }
        }

        match tree.get(key_ref)? {
            Some(bytes) => Ok(Some(T::from_bytes(&bytes)?)),
            None => Ok(None)
        }
    }

    pub fn load_from_disk_internal<T: Serializer, K: AsRef<[u8]>>(snapshot: Option<&Snapshot>, tree: &Tree, key: K, context: DiskContext) -> Result<T, BlockchainError> {
        trace!("load from disk internal");
        Self::load_optional_from_disk_internal(snapshot, tree, key)?
            .ok_or(BlockchainError::NotFoundOnDisk(context))
    }

    // Load an optional value from the DB
    pub(super) fn load_optional_from_disk<T: Serializer, K: AsRef<[u8]>>(&self, tree: &Tree, key: K) -> Result<Option<T>, BlockchainError> {
        trace!("load optional from disk");
        Self::load_optional_from_disk_internal(self.snapshot.as_ref(), tree, key)
    }

    // Load a value from the DB
    pub(super) fn load_from_disk<T: Serializer, K: AsRef<[u8]>>(&self, tree: &Tree, key: K, context: DiskContext) -> Result<T, BlockchainError> {
        trace!("load from disk");
        self.load_optional_from_disk(tree, key)?
            .ok_or(BlockchainError::NotFoundOnDisk(context))
    }

    // Scan prefix over keys only
    pub(super) fn scan_prefix_keys<'a, K: Serializer + 'a>(snapshot: Option<&'a Snapshot>, tree: &Tree, prefix: &[u8]) -> impl Iterator<Item = Result<K, BlockchainError>> + 'a {
        match snapshot {
            Some(snapshot) => Either::Left(snapshot.lazy_iter_keys(tree.into(), IteratorMode::WithPrefix(prefix, Direction::Forward), tree.iter())),
            None => Either::Right(tree.scan_prefix(prefix).into_iter().keys().map(|res| {
                let bytes = res?;
                let k = K::from_bytes(&bytes)?;
                Ok(k)
            }))
        }
    }

    // Scan prefix raw
    pub(super) fn scan_prefix_raw<'a>(snapshot: Option<&'a Snapshot>, tree: &Tree, prefix: &[u8]) -> impl Iterator<Item = Result<(BytesView<'a>, BytesView<'a>), BlockchainError>> + 'a {
        match snapshot {
            Some(snapshot) => Either::Left(snapshot.lazy_iter_raw(tree.into(), IteratorMode::WithPrefix(prefix, Direction::Forward), tree.iter())),
            None => Either::Right(tree.scan_prefix(prefix).into_iter().map(|res| {
                let (k, v) = res?;
                Ok((k.into(), v.into()))
            }))
        }
    }

    // Scan prefix
    pub(super) fn scan_prefix<'a, K: Serializer + 'a, V: Serializer + 'a>(snapshot: Option<&'a Snapshot>, tree: &Tree, prefix: &[u8]) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a {
        Self::scan_prefix_raw(snapshot, tree, prefix).map(|res| {
            let (k_bytes, v_bytes) = res?;
            let k = K::from_bytes(&k_bytes)?;
            let v = V::from_bytes(&v_bytes)?;
            Ok((k, v))
        })
    }

    // Iter raw over a tree entries
    pub(super) fn iter_raw<'a>(snapshot: Option<&'a Snapshot>, tree: &Tree) -> impl Iterator<Item = Result<(BytesView<'a>, BytesView<'a>), BlockchainError>> + 'a {
        match snapshot {
            Some(snapshot) => Either::Left(snapshot.lazy_iter_raw(tree.into(), IteratorMode::Start, tree.iter())),
            None => Either::Right(tree.iter().map(|res| {
                let (k, v) = res?;
                Ok((k.into(), v.into()))
            }))
        }
    }

    // Iter over a tree entries
    pub(super) fn iter<'a, K: Serializer + 'a, V: Serializer + 'a>(snapshot: Option<&'a Snapshot>, tree: &Tree) -> impl Iterator<Item = Result<(K, V), BlockchainError>> + 'a {
        Self::iter_raw(snapshot, tree).map(|res| {
            let (k_bytes, v_bytes) = res?;
            let k = K::from_bytes(&k_bytes)?;
            let v = V::from_bytes(&v_bytes)?;
            Ok((k, v))
        })
    }

    // Iter over a tree keys
    pub(super) fn iter_keys<'a, K: Serializer + 'a>(snapshot: Option<&'a Snapshot>, tree: &Tree) -> impl Iterator<Item = Result<K, BlockchainError>> + 'a {
        Self::iter_raw(snapshot, tree).map(|res| {
            let (k_bytes, _) = res?;
            let k = K::from_bytes(&k_bytes)?;
            Ok(k)
        })
    }

    pub(super) fn remove_from_disk_internal<T: Serializer, K: AsRef<[u8]>>(snapshot: Option<&mut Snapshot>, tree: &Tree, key: K) -> Result<Option<T>, BlockchainError> {
        trace!("remove from disk internal");
        let key_ref = key.as_ref();
        let prev = if let Some(snapshot) = snapshot {
            match snapshot.delete(tree.into(), key_ref.to_vec()) {
                EntryState::Stored(prev) => Some(T::from_bytes(&prev)?),
                EntryState::Deleted => None,
                EntryState::Absent => {
                    // Fallback to the disk for the previous value
                    tree.get(key_ref)?
                        .map(|bytes| T::from_bytes(&bytes))
                        .transpose()?
                }
            }
        } else {
            tree.remove(key_ref)?
                .map(|bytes| T::from_bytes(&bytes))
                .transpose()?
        };

        Ok(prev)
    }

    pub (super) fn remove_from_disk_without_reading(snapshot: Option<&mut Snapshot>, tree: &Tree, key: &[u8]) -> Result<bool, BlockchainError> {
        trace!("remove from disk internal without reading");

        let v = if let Some(snapshot) = snapshot {
            match snapshot.delete(tree.into(), key.to_vec()) {
                EntryState::Stored(_) => true,
                EntryState::Deleted => false,
                EntryState::Absent => {
                    // Fallback to the disk for the previous value
                    tree.contains_key(key)?
                }
            }
        } else {
            tree.remove(key)?.is_some()
        };

        Ok(v)
    }

    // Delete a key from the DB
    pub(super) fn remove_from_disk<T: Serializer, K: AsRef<[u8]>>(snapshot: Option<&mut Snapshot>, tree: &Tree, key: K) -> Result<Option<T>, BlockchainError> {
        trace!("remove from disk");
        Self::remove_from_disk_internal(snapshot, tree, key)
    }

    // Insert a key into the DB
    // Returns true if the key was already present
    pub(super) fn insert_into_disk<K: AsRef<[u8]>, V: Into<IVec>>(snapshot: Option<&mut Snapshot>, tree: &Tree, key: K, value: V) -> Result<bool, BlockchainError> {
        Self::insert_into_disk_read::<K, V, ()>(snapshot, tree, key, value)
            .map(|prev| prev.is_some())
    }

    // Insert a key into the DB
    pub(super) fn insert_into_disk_read<K: AsRef<[u8]>, V: Into<IVec>, R: Serializer>(snapshot: Option<&mut Snapshot>, tree: &Tree, key: K, value: V) -> Result<Option<R>, BlockchainError> {
        let prev = if let Some(snapshot) = snapshot {
            let value = value.into();
            let v: &[u8] = &value;
            match snapshot.put(tree.into(), key.as_ref().to_vec(), v.to_vec()) {
                EntryState::Stored(prev) => Some(R::from_bytes(&prev)?),
                EntryState::Deleted => None,
                EntryState::Absent => {
                    // Fallback to the disk for the previous value
                    tree.get(key.as_ref())?
                        .map(|bytes| R::from_bytes(&bytes))
                        .transpose()?
                },
            }
        } else {
            tree.insert(key.as_ref(), value)?
                .map(|bytes| R::from_bytes(&bytes))
                .transpose()?
        };

        Ok(prev)
    }

    // Retrieve the exact size of a value from the DB
    pub(super) fn get_size_from_disk(&self, tree: &Tree, key: &[u8]) -> Result<usize, BlockchainError> {
        trace!("get size from disk");

        if let Some(v) = self.snapshot.as_ref().map(|s| s.get(tree.into(), key)) {
            match v {
                EntryState::Stored(bytes) => {
                    return Ok(bytes.len());
                }
                EntryState::Deleted => {
                    return Err(BlockchainError::NotFoundOnDisk(DiskContext::DataLen));
                }
                EntryState::Absent => {}
            }
        }

        let len = tree.get(key)?
            .ok_or(BlockchainError::NotFoundOnDisk(DiskContext::DataLen))?
            .len();
        Ok(len)
    }

    // Load from disk and cache the value
    // Or load it from cache if available
    // Note that the Snapshot has no cache and is priority over the cache
    // This mean, cache is never used if a snapshot is available
    pub(super) async fn get_cacheable_arc_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: Option<&Mutex<LruCache<K, Arc<V>>>>, key: &K, context: DiskContext) -> Result<Immutable<V>, BlockchainError> {
        trace!("get cacheable arc data {:?}", context);
        let key_bytes = key.to_bytes();
        let value = if let Some(cache) = cache.as_ref()
            .filter(|_| self.snapshot.as_ref()
                .map(|s| !s.contains_key(tree.into(), &key_bytes))
                .unwrap_or(true)
            )
        {
            trace!("load arc from cache");
            let mut cache = cache.lock().await;
            if let Some(value) = cache.get(key) {
                trace!("found key in cache, cloning Arc");
                return Ok(Immutable::Arc(Arc::clone(&value)));
            }

            trace!("no arc found in cache, loading from disk");
            let value = Arc::new(self.load_from_disk(tree, &key_bytes, context)?);

            trace!("inserting arced data into the cache");
            cache.put(key.clone(), Arc::clone(&value));
            Immutable::Arc(value)
        } else {
            trace!("no cache or snapshot enabled, load from disk");
            Immutable::Owned(self.load_from_disk(tree, &key_bytes, context)?)
        };

        Ok(value)
    }

    pub(super) async fn get_optional_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer + Clone>(&self, tree: &Tree, cache: Option<&Mutex<LruCache<K, V>>>, key: &K) -> Result<Option<V>, BlockchainError> {
        trace!("get optional cacheable data");
        let key_bytes = key.to_bytes();
        let value = if let Some(cache) = cache.as_ref()
            .filter(|_| self.snapshot.as_ref()
                .map_or(true, |s| !s.contains_key(tree.into(), &key_bytes))
            )
        {
            trace!("load optional from cache");
            let mut cache = cache.lock().await;
            if let Some(value) = cache.get(key).cloned() {
                trace!("data is present in cache");
                return Ok(Some(value));
            }

            trace!("not found in cache, load optional from disk");
            let value: Option<V> = self.load_optional_from_disk(tree, &key_bytes)?;

            trace!("load optional from disk is present: {}", value.is_some());
            if let Some(value) = value.as_ref() {
                cache.put(key.clone(), value.clone());
            }

            value
        } else {
            self.load_optional_from_disk(tree, &key_bytes)?
        };

        Ok(value)
    }

    // Load a value from the DB and cache it
    // This data is not cached behind an Arc, but is cloned at each access
    pub(super) async fn get_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer + Clone>(&self, tree: &Tree, cache: Option<&Mutex<LruCache<K, V>>>, key: &K, context: DiskContext) -> Result<V, BlockchainError> {
        trace!("get cacheable data {:?}", context);
        self.get_optional_cacheable_data(tree, cache, key).await?
            .ok_or_else(|| BlockchainError::NotFoundOnDisk(DiskContext::LoadData))
    }

    pub(super) async fn delete_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(snapshot: Option<&mut Snapshot>, tree: &Tree, cache: Option<&mut Mutex<LruCache<K, V>>>, key: &K) -> Result<V, BlockchainError> {
        trace!("delete cacheable data");

        let k = key.to_bytes();
        if let Some(cache) = cache {
            if let Some(v) = cache.get_mut().pop(key) {
                trace!("data has been deleted from cache");

                Self::remove_from_disk_without_reading(snapshot, tree, &k)?;
                return Ok(v)
            }
        }

        let value = Self::load_optional_from_disk_internal::<V, _>(snapshot.as_deref(), tree, &k)?
            .ok_or(BlockchainError::NotFoundOnDisk(DiskContext::DeleteData))?;

        Self::remove_from_disk_without_reading(snapshot, tree, &k)?;

        // Lazy read
        Ok(value)
    }

    // Delete a cacheable data from disk and cache behind a Arc
    pub(super) async fn delete_arc_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(snapshot: Option<&mut Snapshot>, tree: &Tree, cache: Option<&mut Mutex<LruCache<K, Arc<V>>>>, key: &K) -> Result<Immutable<V>, BlockchainError> {
        trace!("delete arc cacheable data");
        let value = match Self::remove_from_disk::<V, _>(snapshot, tree, &key.to_bytes())? {
            Some(data) => data,
            None => return Err(BlockchainError::NotFoundOnDisk(DiskContext::DeleteData))
        };

        if let Some(cache) = cache {
            if let Some(v) = cache.get_mut().pop(key) {
                trace!("data has been deleted from arc cache");
                return Ok(Immutable::Arc(v))
            }
        }

        Ok(Immutable::Owned(value))
    }

    // Check if our DB contains a data in cache or on disk
    pub(super) async fn contains_data_cached<K: Eq + StdHash + Serializer + Clone, V>(&self, tree: &Tree, cache: Option<&Mutex<LruCache<K, V>>>, key: &K) -> Result<bool, BlockchainError> {
        trace!("contains data cached");

        let key_bytes = key.to_bytes();
        if let Some(snapshot) = self.snapshot.as_ref() {
            if let Some(v) = snapshot.contains(tree.into(), &key_bytes) {
                trace!("snapshot contains requested data");
                return Ok(v);
            }
        }

        if let Some(cache) = cache {
            let cache = cache.lock().await;
            if cache.contains(key) {
                trace!("cache contains requested data");
                return Ok(true);
            }
        }

        Ok(tree.contains_key(&key_bytes)?)
    }

    // Check if our DB contains a data on disk
    pub(super) fn contains_data<K: AsRef<[u8]>>(&self, tree: &Tree, key: K) -> Result<bool, BlockchainError> {
        trace!("contains data");
        let key_bytes = key.as_ref();
        if let Some(snapshot) = self.snapshot.as_ref() {
            if let Some(v) = snapshot.contains(tree.into(), key_bytes) {
                trace!("snapshot contains data");
                return Ok(v);
            }
        }

        Ok(tree.contains_key(&key_bytes)?)
    }

    // Update the assets count and store it on disk
    pub(super) fn store_assets_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        trace!("store assets count {}", count);

        self.cache_mut().assets_count = count;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, ASSETS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }
}

#[async_trait]
impl Storage for SledStorage {
    // Delete the whole block using its topoheight
    async fn delete_block_at_topoheight(&mut self, topoheight: u64) -> Result<(Hash, Immutable<BlockHeader>), BlockchainError> {
        trace!("Delete block at topoheight {topoheight}");

        // delete topoheight<->hash pointers
        let hash = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.hash_at_topo, self.cache.objects.as_mut().map(|o| &mut o.hash_at_topo_cache), &topoheight).await?;

        trace!("Deleting block execution order");
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.blocks_execution_order, hash.as_bytes())?;

        trace!("Hash is {hash} at topo {topoheight}");

        Self::delete_cacheable_data::<Hash, u64>(self.snapshot.as_mut(), &self.topo_by_hash, self.cache.objects.as_mut().map(|o| &mut o.topo_by_hash_cache), &hash).await?;

        trace!("deleting block header {}", hash);
        let block = self.delete_block_by_hash(&hash).await?;
        trace!("block header deleted successfully");

        trace!("Deleting topoheight metadata");
        let _: () = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.topoheight_metadata, None, &topoheight).await?;

        for tx_hash in block.get_transactions() {
            if self.is_tx_executed_in_block(tx_hash, &hash).await? {
                trace!("Tx {} was executed, deleting", tx_hash);
                self.unmark_tx_from_executed(&tx_hash).await?;
                self.delete_contract_logs_for_caller(&tx_hash).await?;
            }

            // Because the TX is not linked to any other block, we can safely delete that block
            if !self.is_tx_linked_to_blocks(&tx_hash).await? {
                trace!("Deleting TX {} in block {}", tx_hash, hash);
                let _: Immutable<Transaction> = Self::delete_arc_cacheable_data(self.snapshot.as_mut(), &self.transactions, self.cache.objects.as_mut().map(|o| &mut o.transactions_cache), tx_hash).await?;
            }
        }

        Ok((hash, block))
    }

    // Returns the current size on disk in bytes
    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError> {
        let size = self.db.size_on_disk()
            .context("Failed to get size on disk")?;
        Ok(size)
    }

    async fn stop(&mut self) -> Result<(), BlockchainError> {
        info!("Stopping Storage...");
        info!("Flushing Sled database");
        self.db.flush_async().await
            .context("Failed to flush sled database")?;
        info!("Sled database flushed");
        Ok(())
    }

    async fn estimate_size(&self) -> Result<u64, BlockchainError> {
        trace!("Estimating size");

        let mut size = 0;
        for tree in self.db.tree_names() {
            let tree = self.db.open_tree(tree)
                .context("Failed to open sled tree")?;
            debug!("Estimating size for tree {}", String::from_utf8_lossy(&tree.name()));
            for el in Self::iter_raw(self.snapshot.as_ref(), &tree) {
                let (key, value) = el?;
                size += key.len() + value.len();
            }
        }

        Ok(size as u64)
    }

    async fn flush(&mut self) -> Result<(), BlockchainError> {
        trace!("flush sled");
        let n = self.db.flush_async().await
            .context("Failed to flush sled database")?;

        debug!("Flushed {} bytes", n);
        Ok(())
    }
}