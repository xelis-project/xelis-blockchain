mod snapshot;

use anyhow::Context;
use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_vm::Environment;
use crate::{
    config::PRUNE_SAFETY_LIMIT,
    core::error::{BlockchainError, DiskContext}
};
use xelis_common::{
    block::{TopoHeight, Block, BlockHeader},
    crypto::{Hash, PublicKey},
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    network::Network,
    serializer::{Reader, Serializer},
    transaction::Transaction
};
use std::{
    collections::HashSet,
    hash::Hash as StdHash,
    num::NonZeroUsize,
    str::FromStr,
    sync::Arc
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use lru::LruCache;
use sled::{IVec, Tree};
use log::{debug, trace, warn, info};

pub use snapshot::Snapshot;

use super::{
    providers::*,
    Storage,
    Tips
};

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

pub struct SledStorage {
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
    // cumulative difficulty for each block hash on disk
    pub(super) cumulative_difficulty: Tree,
    // Difficulty estimated covariance (P)
    pub(super) difficulty_covariance: Tree,
    // keep tracks of all available assets on network
    pub(super) assets: Tree,
    // account nonces to prevent TX replay attack
    pub(super) nonces: Tree,
    // block reward for each block topoheight
    pub(super) rewards: Tree,
    // supply for each block topoheight
    pub(super) supply: Tree,
    // burned supply for each block topoheight
    pub(super) burned_supply: Tree,
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
    pub(super) versioned_contracts: Tree,
    // opened DB used for assets to create dynamic assets
    pub(super) db: sled::Db,

    // all available caches
    // Transaction cache
    pub(super) transactions_cache: Option<Mutex<LruCache<Hash, Arc<Transaction>>>>,
    // Block header cache
    pub(super) blocks_cache: Option<Mutex<LruCache<Hash, Arc<BlockHeader>>>>,
    // Blocks Tips cache
    pub(super) past_blocks_cache: Option<Mutex<LruCache<Hash, Arc<IndexSet<Hash>>>>>,
    // Topoheight by hash cache
    pub(super) topo_by_hash_cache: Option<Mutex<LruCache<Hash, TopoHeight>>>,
    // Hash by topoheight cache
    pub(super) hash_at_topo_cache: Option<Mutex<LruCache<TopoHeight, Hash>>>,
    // Cumulative difficulty cache
    pub(super) cumulative_difficulty_cache: Option<Mutex<LruCache<Hash, CumulativeDifficulty>>>,
    // Assets cache
    pub(super) assets_cache: Option<Mutex<LruCache<Hash, ()>>>,
    // Tips cache: current chain Tips
    pub(super) tips_cache: Tips,
    // Pruned topoheight cache
    pub(super) pruned_topoheight: Option<TopoHeight>,

    // Cache for counters
    // Count of assets
    pub(super) assets_count: u64,
    // Count of accounts
    pub(super) accounts_count: u64,
    // Count of transactions
    pub(super) transactions_count: u64,
    // Count of blocks
    pub(super) blocks_count: u64,
    // Count of blocks added in chain
    pub(super) blocks_execution_count: u64,
    // Count of contracts deployed
    pub(super) contracts_count: u64,

    // If we have a snapshot, we can use it to rollback
    pub(super) snapshot: Option<Snapshot>,
    // Contract environment for the stdlib
    pub(super) environment: Environment
}

macro_rules! init_cache {
    ($cache_size: expr) => {{
        if let Some(size) = &$cache_size {
            Some(Mutex::new(LruCache::new(NonZeroUsize::new(*size).unwrap())))
        } else {
            None
        }
    }};
}

#[derive(Clone, Copy, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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

// Default cache size
const DEFAULT_DB_CACHE_CAPACITY: u64 = 16 * 1024 * 1024; // 16 MB

impl SledStorage {
    pub fn new(dir_path: String, cache_size: Option<usize>, network: Network, internal_cache_size: Option<u64>, mode: StorageMode) -> Result<Self, BlockchainError> {
        let path = format!("{}{}", dir_path, network.to_string().to_lowercase());
        let config = sled::Config::new()
            .temporary(false)
            .path(path)
            .cache_capacity(internal_cache_size.unwrap_or(DEFAULT_DB_CACHE_CAPACITY))
            .mode(mode.into());

        let sled = config.open()?;

        let mut storage = Self {
            network,
            transactions: sled.open_tree("transactions")?,
            txs_executed: sled.open_tree("txs_executed")?,
            blocks_execution_order: sled.open_tree("blocks_execution_order")?,
            blocks: sled.open_tree("blocks")?,
            blocks_at_height: sled.open_tree("blocks_at_height")?,
            extra: sled.open_tree("extra")?,
            topo_by_hash: sled.open_tree("topo_at_hash")?,
            hash_at_topo: sled.open_tree("hash_at_topo")?,
            cumulative_difficulty: sled.open_tree("cumulative_difficulty")?,
            difficulty_covariance: sled.open_tree("difficulty_covariance")?,
            assets: sled.open_tree("assets")?,
            nonces: sled.open_tree("nonces")?,
            rewards: sled.open_tree("rewards")?,
            supply: sled.open_tree("supply")?,
            burned_supply: sled.open_tree("burned_supply")?,
            difficulty: sled.open_tree("difficulty")?,
            tx_blocks: sled.open_tree("tx_blocks")?,
            versioned_nonces: sled.open_tree("versioned_nonces")?,
            balances: sled.open_tree("balances")?,
            multisig: sled.open_tree("multisig")?,
            versioned_multisigs: sled.open_tree("versioned_multisig")?,
            versioned_balances: sled.open_tree("versioned_balances")?,
            merkle_hashes: sled.open_tree("merkle_hashes")?,
            registrations: sled.open_tree("registrations")?,
            registrations_prefixed: sled.open_tree("registrations_prefixed")?,
            contracts: sled.open_tree("contracts")?,
            versioned_contracts: sled.open_tree("versioned_contracts")?,
            db: sled,
            transactions_cache: init_cache!(cache_size),
            blocks_cache: init_cache!(cache_size),
            past_blocks_cache: init_cache!(cache_size),
            topo_by_hash_cache: init_cache!(cache_size),
            hash_at_topo_cache: init_cache!(cache_size),
            cumulative_difficulty_cache: init_cache!(cache_size),
            assets_cache: init_cache!(cache_size),
            tips_cache: HashSet::new(),
            pruned_topoheight: None,
            assets_count: 0,
            accounts_count: 0,
            transactions_count: 0,
            blocks_count: 0,
            blocks_execution_count: 0,
            contracts_count: 0,

            snapshot: None,
            environment: Environment::default()
        };

        // Verify that we are opening a DB on same network
        // This prevent any corruption made by user
        if storage.has_network()? {
            let storage_network = storage.load_from_disk::<Network>(&storage.extra, NETWORK, DiskContext::Network)?;
            if storage_network != network {
                return Err(BlockchainError::InvalidNetwork);
            }
        } else {
            storage.set_network(&network)?;
        }

        storage.load_cache();

        Ok(storage)
    }

    fn load_cache(&mut self) {
        // Load tips from disk if available
        if let Ok(tips) = self.load_from_disk::<Tips>(&self.extra, TIPS, DiskContext::Tips) {
            debug!("Found tips: {}", tips.len());
            self.tips_cache = tips;
        }

        // Load the pruned topoheight from disk if available
        if let Ok(pruned_topoheight) = self.load_from_disk::<u64>(&self.extra, PRUNED_TOPOHEIGHT, DiskContext::PrunedTopoHeight) {
            debug!("Found pruned topoheight: {}", pruned_topoheight);
            self.pruned_topoheight = Some(pruned_topoheight);
        }

        // Load the assets count from disk if available
        if let Ok(assets_count) = self.load_from_disk::<u64>(&self.extra, ASSETS_COUNT, DiskContext::AssetsCount) {
            debug!("Found assets count: {}", assets_count);
            self.assets_count = assets_count;
        }

        // Load the txs count from disk if available
        if let Ok(txs_count) = self.load_from_disk::<u64>(&self.extra, TXS_COUNT, DiskContext::TxsCount) {
            debug!("Found txs count: {}", txs_count);
            self.transactions_count = txs_count;
        }

        // Load the blocks count from disk if available
        if let Ok(blocks_count) = self.load_from_disk::<u64>(&self.extra, BLOCKS_COUNT, DiskContext::BlocksCount) {
            debug!("Found blocks count: {}", blocks_count);
            self.blocks_count = blocks_count;
        }

        // Load the accounts count from disk if available
        if let Ok(accounts_count) = self.load_from_disk::<u64>(&self.extra, ACCOUNTS_COUNT, DiskContext::AccountsCount) {
            debug!("Found accounts count: {}", accounts_count);
            self.accounts_count = accounts_count;
        }

        // Load the blocks execution count from disk if available
        if let Ok(blocks_execution_count) = self.load_from_disk::<u64>(&self.extra, BLOCKS_EXECUTION_ORDER_COUNT, DiskContext::BlocksExecutionOrderCount) {
            debug!("Found blocks execution count: {}", blocks_execution_count);
            self.blocks_execution_count = blocks_execution_count;
        }

        // Load the contracts count from disk if available
        if let Ok(contracts_count) = self.load_from_disk::<u64>(&self.extra, CONTRACTS_COUNT, DiskContext::ContractsCount) {
            debug!("Found contracts count: {}", contracts_count);
            self.contracts_count = contracts_count;
        }
    }

    // Load an optional value from the DB
    pub(super) fn load_optional_from_disk<T: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<Option<T>, BlockchainError> {
        trace!("load optional from disk");
        if let Some(snapshot) = self.snapshot.as_ref() {
            trace!("load from snapshot");
            if snapshot.contains_key(tree, key) {
                trace!("load from snapshot key {:?} from db", key);
                return snapshot.load_optional_from_disk(tree, key);
            }
        }

        match tree.get(key)? {
            Some(bytes) => {
                let bytes = bytes.to_vec();
                let mut reader = Reader::new(&bytes);
                let value = T::read(&mut reader)?;
                Ok(Some(value))
            },
            None => Ok(None)
        }
    }

    // Load a value from the DB
    pub(super) fn load_from_disk<T: Serializer>(&self, tree: &Tree, key: &[u8], context: DiskContext) -> Result<T, BlockchainError> {
        trace!("load from disk");
        self.load_optional_from_disk(tree, key)?
            .ok_or(BlockchainError::NotFoundOnDisk(context))
    }

    // Delete a key from the DB
    pub(super) fn remove_from_disk(snapshot: Option<&mut Snapshot>, tree: &Tree, key: &[u8]) -> Result<Option<IVec>, BlockchainError> {
        if let Some(snapshot) = snapshot {
            if snapshot.contains_key(tree, key) {
                let (value, load) = snapshot.remove(tree, key);
                return Ok(if load {
                    info!("Rollback: loading key {:?} from db", key);
                    tree.get(key)?
                } else {
                    value
                })
            }
        }

        let data = tree.remove(key)?;
        Ok(data)
    }

    // Delete a key from the DB without reading it
    pub(super) fn remove_from_disk_without_reading(snapshot: Option<&mut Snapshot>, tree: &Tree, key: &[u8]) -> Result<bool, BlockchainError> {
        if let Some(snapshot) = snapshot {
            if snapshot.contains_key(tree, key) {
                let (v, _ ) = snapshot.remove(tree, key);
                return Ok(v.is_some());
            }
        }

        let v = tree.remove(key)?;
        Ok(v.is_some())
    }

    // Insert a key into the DB
    pub(super) fn insert_into_disk<K: AsRef<[u8]>, V: Into<IVec>>(snapshot: Option<&mut Snapshot>, tree: &Tree, key: K, value: V) -> Result<Option<IVec>, BlockchainError> {
        let previous = if let Some(snapshot) = snapshot {
            let r = key.as_ref();
            snapshot.insert(tree, r, value)
        } else {
            tree.insert(key, value)?
        };

        Ok(previous)
    }

    pub(super) fn get_len_for(&self, tree: &Tree, key: &[u8]) -> Result<usize, BlockchainError> {
        if let Some(snapshot) = self.snapshot.as_ref() {
            if snapshot.contains_key(tree, key) {
                return snapshot.get_len_for(tree, key).ok_or(BlockchainError::NotFoundOnDisk(DiskContext::DataLen));
            }
        }

        let len = tree.get(key)?
            .ok_or(BlockchainError::NotFoundOnDisk(DiskContext::DataLen))?
            .len();
        Ok(len)
    }

    // Drop a tree from the DB
    pub(super) fn drop_tree<V: AsRef<[u8]>>(snapshot: Option<&mut Snapshot>, db: &sled::Db, tree_name: V) -> Result<bool, BlockchainError> {
        let v = if let Some(snapshot) = snapshot {
            snapshot.drop_tree(tree_name)
        } else {
            db.drop_tree(tree_name)?
        };

        Ok(v)
    }

    // Load from disk and cache the value
    // Or load it from cache if available
    // Note that the Snapshot has no cache and is priority over the cache
    // This mean, cache is never used if a snapshot is available
    pub(super) async fn get_cacheable_arc_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, Arc<V>>>>, key: &K, context: DiskContext) -> Result<Arc<V>, BlockchainError> {
        let key_bytes = key.to_bytes();
        let value = if let Some(cache) = cache.as_ref()
            .filter(|_| self.snapshot.as_ref()
                .map(|s| !s.contains_key(tree, &key_bytes))
                .unwrap_or(true)
            )
        {
            let mut cache = cache.lock().await;
            if let Some(value) = cache.get(key) {
                return Ok(Arc::clone(&value));
            }

            let value = Arc::new(self.load_from_disk(tree, &key_bytes, context)?);
            cache.put(key.clone(), Arc::clone(&value));
            value
        } else {
            Arc::new(self.load_from_disk(tree, &key_bytes, context)?)
        };

        Ok(value)
    }

    // Load a value from the DB and cache it
    // This data is not cached behind an Arc, but is cloned at each access
    pub(super) async fn get_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer + Clone>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K, context: DiskContext) -> Result<V, BlockchainError> {
        let key_bytes = key.to_bytes();
        let value = if let Some(cache) = cache.as_ref()
            .filter(|_| self.snapshot.as_ref()
                .map(|s| !s.contains_key(tree, &key_bytes))
                .unwrap_or(true)
            )
        {
            trace!("load from cache");
            let mut cache = cache.lock().await;
            if let Some(value) = cache.get(key) {
                return Ok(value.clone());
            }

            let value: V = self.load_from_disk(tree, &key_bytes, context)?;
            cache.put(key.clone(), value.clone());
            value
        } else {
            self.load_from_disk(tree, &key_bytes, context)?
        };

        Ok(value)
    }

    pub(super) async fn delete_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(snapshot: Option<&mut Snapshot>, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<V, BlockchainError> {
        let bytes = match Self::remove_from_disk(snapshot, tree, &key.to_bytes())? {
            Some(data) => data.to_vec(),
            None => return Err(BlockchainError::NotFoundOnDisk(DiskContext::DeleteData))
        };

        if let Some(cache) = cache {
            let mut cache = cache.lock().await;
            if let Some(value) = cache.pop(key) {
                return Ok(value);
            }
        }

        let mut reader = Reader::new(&bytes);
        let value = V::read(&mut reader)?;
        Ok(value)
    }

    // Delete a cacheable data from disk and cache behind a Arc
    pub(super) async fn delete_arc_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(snapshot: Option<&mut Snapshot>, tree: &Tree, cache: &Option<Mutex<LruCache<K, Arc<V>>>>, key: &K) -> Result<Arc<V>, BlockchainError> {
        let bytes = match Self::remove_from_disk(snapshot, tree, &key.to_bytes())? {
            Some(data) => data.to_vec(),
            None => return Err(BlockchainError::NotFoundOnDisk(DiskContext::DeleteData))
        };

        if let Some(cache) = cache {
            let mut cache = cache.lock().await;
            if let Some(value) = cache.pop(key) {
                return Ok(value);
            }
        }

        let mut reader = Reader::new(&bytes);
        let value = V::read(&mut reader)?;
        Ok(Arc::new(value))
    }

    // Check if our DB contains a data in cache or on disk
    pub(super) async fn contains_data_cached<K: Eq + StdHash + Serializer + Clone, V>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<bool, BlockchainError> {
        let key_bytes = key.to_bytes();
        if let Some(snapshot) = self.snapshot.as_ref() {
            if let Some(v) = snapshot.contains_key_with_value(tree, &key_bytes) {
                return Ok(v);
            }
        }

        if let Some(cache) = cache {
            let cache = cache.lock().await;
            if cache.contains(key) {
                return Ok(true);
            }
        }

        Ok(tree.contains_key(&key_bytes)?)
    }

    // Check if our DB contains a data on disk
    pub(super) fn contains_data<K: Serializer>(&self, tree: &Tree, key: &K) -> Result<bool, BlockchainError> {
        let key_bytes = key.to_bytes();
        if let Some(snapshot) = self.snapshot.as_ref() {
            if let Some(v) = snapshot.contains_key_with_value(tree, &key_bytes) {
                return Ok(v);
            }
        }

        Ok(tree.contains_key(&key_bytes)?)
    }

    // Update the assets count and store it on disk
    pub(super) fn store_assets_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.assets_count = count;
        } else {
            self.assets_count = count;
        }

        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, ASSETS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }
}

#[async_trait]
impl Storage for SledStorage {
    async fn clear_caches(&mut self) -> Result<(), BlockchainError> {
        if let Some(cache) = self.transactions_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.blocks_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.past_blocks_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.topo_by_hash_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.hash_at_topo_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.cumulative_difficulty_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.assets_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        // also load the atomic counters from disk
        self.load_cache();

        Ok(())
    }

    // Delete the whole block using its topoheight
    async fn delete_block_at_topoheight(&mut self, topoheight: u64) -> Result<(Hash, Arc<BlockHeader>, Vec<(Hash, Arc<Transaction>)>), BlockchainError> {
        trace!("Delete block at topoheight {topoheight}");

        // delete topoheight<->hash pointers
        let hash = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.hash_at_topo, &self.hash_at_topo_cache, &topoheight).await?;

        trace!("Deleting block execution order");
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.blocks_execution_order, hash.as_bytes())?;

        trace!("Hash is {hash} at topo {topoheight}");

        Self::delete_cacheable_data::<Hash, u64>(self.snapshot.as_mut(), &self.topo_by_hash, &self.topo_by_hash_cache, &hash).await?;

        trace!("deleting block header {}", hash);
        let block = Self::delete_arc_cacheable_data(self.snapshot.as_mut(), &self.blocks, &self.blocks_cache, &hash).await?;
        trace!("block header deleted successfully");

        trace!("Deleting supply");
        let supply: u64 = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.supply, &None, &topoheight).await?;
        trace!("Supply was {}", supply);

        trace!("Deleting burned supply");
        let burned_supply: u64 = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.burned_supply, &None, &topoheight).await?;
        trace!("Burned supply was {}", burned_supply);

        trace!("Deleting rewards");
        let reward: u64 = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.rewards, &None, &topoheight).await?;
        trace!("Reward for block {} was: {}", hash, reward);

        trace!("Deleting difficulty");
        let _: Difficulty = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.difficulty, &None, &hash).await?;

        trace!("Deleting cumulative difficulty");
        let cumulative_difficulty: CumulativeDifficulty = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.cumulative_difficulty, &self.cumulative_difficulty_cache, &hash).await?;
        trace!("Cumulative difficulty deleted: {}", cumulative_difficulty);

        let mut txs = Vec::new();
        for tx_hash in block.get_transactions() {
            // Should we delete the tx too or only unlink it
            let mut should_delete = true;
            if self.has_tx_blocks(tx_hash)? {
                let mut blocks: Tips = Self::delete_cacheable_data(self.snapshot.as_mut(), &self.tx_blocks, &None, tx_hash).await?;
                let blocks_len =  blocks.len();
                blocks.remove(&hash);
                should_delete = blocks.is_empty();
                self.set_blocks_for_tx(tx_hash, &blocks)?;
                trace!("Tx was included in {}, blocks left: {}", blocks_len, blocks.into_iter().map(|b| b.to_string()).collect::<Vec<String>>().join(", "));
            }

            if self.is_tx_executed_in_a_block(tx_hash)? {
                trace!("Tx {} was executed, deleting", tx_hash);
                self.remove_tx_executed(&tx_hash)?;
            }

            // We have to check first as we may have already deleted it because of client protocol
            // which allow multiple time the same txs in differents blocks
            if should_delete && self.contains_data_cached(&self.transactions, &self.transactions_cache, tx_hash).await? {
                trace!("Deleting TX {} in block {}", tx_hash, hash);
                let tx: Arc<Transaction> = Self::delete_arc_cacheable_data(self.snapshot.as_mut(), &self.transactions, &self.transactions_cache, tx_hash).await?;
                txs.push((tx_hash.clone(), tx));
            }
        }

        // remove the block hash from the set, and delete the set if empty
        if self.has_blocks_at_height(block.get_height()).await? {
            self.remove_block_hash_at_height(&hash, block.get_height()).await?;
        }

        // Delete cache of past blocks
        if let Some(cache) = &self.past_blocks_cache {
            let mut cache = cache.lock().await;
            cache.pop(&hash);
        }

        Ok((hash, block, txs))
    }

    // The first versioned balance that is under the topoheight is bumped to topoheight
    async fn create_snapshot_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        // asset tree where PublicKey are stored with the highest balance topoheight in it
        for el in self.balances.iter() {
            let (key_bytes, value) = el?;
            let key = PublicKey::from_bytes(&key_bytes[0..32])?;
            let asset = Hash::from_bytes(&key_bytes[32..64])?;
            let highest_balance_topoheight = u64::from_bytes(&value)?;

            // retrieve the highest versioned balance
            let mut versioned_balance = self.get_balance_at_exact_topoheight(&key, &asset, highest_balance_topoheight).await?;

            // if the highest topoheight for this account is less than the snapshot topoheight
            // update it to the topoheight
            // otherwise, delete the previous topoheight in VersionedBalance which is under topoheight
            if highest_balance_topoheight <= topoheight {
                // save the new highest topoheight
                Self::insert_into_disk(self.snapshot.as_mut(), &self.balances, &key_bytes, &topoheight.to_be_bytes())?;

                // remove the previous topoheight
                versioned_balance.set_previous_topoheight(None);

                // save it
                let key = self.get_versioned_balance_key(&key, &asset, topoheight);
                Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_balances, &key, versioned_balance.to_bytes())?;
            } else {
                // find the first VersionedBalance which is under topoheight
                let mut current_version_topoheight = highest_balance_topoheight;
                while let Some(previous_topoheight) = versioned_balance.get_previous_topoheight() {
                    if previous_topoheight <= topoheight {
                        // update the current versioned balance that refer to the pruned versioned balance
                        {
                            versioned_balance.set_previous_topoheight(Some(topoheight));
                            let key = self.get_versioned_balance_key(&key, &asset, current_version_topoheight);
                            Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_balances, &key, versioned_balance.to_bytes())?;
                        }
                        
                        // Now update the previous version which is under topoheight
                        {
                            let mut previous_version = self.get_balance_at_exact_topoheight(&key, &asset, previous_topoheight).await?;
                            previous_version.set_previous_topoheight(None);
                            let key = self.get_versioned_balance_key(&key, &asset, topoheight);
                            Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_balances, &key, previous_version.to_bytes())?;
                        }
                        break;
                    }

                    // keep searching
                    versioned_balance = self.get_balance_at_exact_topoheight(&key, &asset, previous_topoheight).await?;
                    current_version_topoheight = previous_topoheight;
                }
            }
        }

        Ok(())
    }

    // The first versioned balance that is under the topoheight is bumped to topoheight
    async fn create_snapshot_nonces_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        // tree where VersionedNonce are stored
        // tree where PublicKey are stored with the highest noce topoheight in it
        for el in self.nonces.iter() {
            let (key_bytes, value) = el?;
            let key = PublicKey::from_bytes(&key_bytes)?;
            let highest_topoheight = TopoHeight::from_bytes(&value)?;

            // retrieve the highest versioned nonce
            let mut versioned_nonce = self.get_nonce_at_exact_topoheight(&key, highest_topoheight).await?;

            // if the highest topoheight for this account is less than the snapshot topoheight
            // update it to the topoheight
            // otherwise, delete the previous topoheight in VersionedNonce which is under topoheight
            if highest_topoheight <= topoheight {
                // save the new highest topoheight
                Self::insert_into_disk(self.snapshot.as_mut(), &self.nonces, &key_bytes, &topoheight.to_be_bytes())?;

                // remove the previous topoheight
                versioned_nonce.set_previous_topoheight(None);

                // save it
                let key = self.get_versioned_nonce_key(&key, topoheight);
                Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_nonces, &key, versioned_nonce.to_bytes())?;
            } else {
                // find the first VersionedBalance which is under topoheight
                let mut current_version_topoheight = highest_topoheight;
                while let Some(previous_topoheight) = versioned_nonce.get_previous_topoheight() {
                    if previous_topoheight <= topoheight {
                        // update the current versioned data that refer to the pruned versioned data
                        {
                            versioned_nonce.set_previous_topoheight(Some(topoheight));
                            let key = self.get_versioned_nonce_key(&key, current_version_topoheight);
                            Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_nonces, &key, versioned_nonce.to_bytes())?;
                        }
                        
                        // Now update the previous version which is under topoheight
                        {
                            let mut previous_version = self.get_nonce_at_exact_topoheight(&key, previous_topoheight).await?;
                            previous_version.set_previous_topoheight(None);
                            let key = self.get_versioned_nonce_key(&key, topoheight);
                            Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_nonces, &key, previous_version.to_bytes())?;
                        }
                        break;
                    }

                    // keep searching
                    versioned_nonce = self.get_nonce_at_exact_topoheight(&key, previous_topoheight).await?;
                    current_version_topoheight = previous_topoheight;
                }
            }
        }

        Ok(())
    }

    async fn create_snapshot_registrations_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("create snapshot registrations at topoheight {}", topoheight);
        // tree where PublicKey are stored with the registration topoheight in it
        let mut buf = [0u8; 40];
        for el in self.registrations.iter() {
            let (key, value) = el?;
            let registration_topo = u64::from_bytes(&value)?;

            // if the registration topoheight for this account is less than the snapshot topoheight
            // update it to the topoheight
            if registration_topo <= topoheight {
                // Delete the prefixed registration
                buf[0..8].copy_from_slice(&value);
                buf[8..40].copy_from_slice(&key);
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.registrations_prefixed, &buf)?;

                // save the new registration topoheight
                Self::insert_into_disk(self.snapshot.as_mut(), &self.registrations, &key, &topoheight.to_be_bytes())?;

                // Overwrite with the new topoheight
                buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
                Self::insert_into_disk(self.snapshot.as_mut(), &self.registrations_prefixed, &buf, &[])?;
            }
        }

        Ok(())
    }

    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: TopoHeight, count: u64, stable_topo_height: TopoHeight) -> Result<(u64, TopoHeight, Vec<(Hash, Arc<Transaction>)>), BlockchainError> {
        trace!("pop blocks from height: {}, topoheight: {}, count: {}", height, topoheight, count);
        if topoheight < count as u64 { // also prevent removing genesis block
            return Err(BlockchainError::NotEnoughBlocks);
        }

        // search the lowest topo height available based on count + 1
        // (last lowest topo height accepted)
        let mut lowest_topo = topoheight - count;
        trace!("Lowest topoheight for rewind: {}", lowest_topo);

        let pruned_topoheight = self.get_pruned_topoheight().await?.unwrap_or(0);

        // we must check that we are stopping a sync block
        // easy way for this: check the block at topo is currently alone at height
        while lowest_topo > pruned_topoheight {
            let hash = self.get_hash_at_topo_height(lowest_topo).await?;
            let block_height = self.get_height_for_block_hash(&hash).await?;
            let blocks_at_height = self.get_blocks_at_height(block_height).await?;
            info!("blocks at height: {}", blocks_at_height.len());
            if blocks_at_height.len() == 1 {
                info!("Sync block found at topoheight {}", lowest_topo);
                break;
            } else {
                warn!("No sync block found at topoheight {} we must go lower if possible", lowest_topo);
                lowest_topo -= 1;
            }
        }

        if pruned_topoheight != 0 {
            let safety_pruned_topoheight = pruned_topoheight + PRUNE_SAFETY_LIMIT;
            if lowest_topo <= safety_pruned_topoheight && stable_topo_height != 0 {
                warn!("Pruned topoheight is {}, lowest topoheight is {}, rewind only until {}", pruned_topoheight, lowest_topo, safety_pruned_topoheight);
                lowest_topo = safety_pruned_topoheight;
            }
        }

        // new TIPS for chain
        let mut tips = self.get_tips().await?;

        // Delete all orphaned blocks tips
        for tip in tips.clone() {
            if !self.is_block_topological_ordered(&tip).await {
                debug!("Tip {} is not ordered, removing", tip);
                tips.remove(&tip);
            }
        }

        // all txs to be rewinded
        let mut txs = Vec::new();
        let mut done = 0;
        'main: loop {
            // stop rewinding if its genesis block or if we reached the lowest topo
            if topoheight <= lowest_topo || topoheight <= stable_topo_height || height == 0 { // prevent removing genesis block
                trace!("Done: {done}, count: {count}, height: {height}, topoheight: {topoheight}, lowest topo: {lowest_topo}, stable topo: {stable_topo_height}");
                break 'main;
            }

            // Delete the hash at topoheight
            let (hash, block, block_txs) = self.delete_block_at_topoheight(topoheight).await?;
            trace!("Block {} at topoheight {} deleted", hash, topoheight);
            txs.extend(block_txs);

            // generate new tips
            trace!("Removing {} from {} tips", hash, tips.len());
            tips.remove(&hash);
 
            for hash in block.get_tips() {
                trace!("Adding {} to {} tips", hash, tips.len());
                tips.insert(hash.clone());
            }

            if topoheight <= pruned_topoheight {
                warn!("Pruned topoheight is reached, this is not healthy, starting from 0");
                topoheight = 0;
                height = 0;

                tips.clear();
                tips.insert(self.get_hash_at_topo_height(0).await?);

                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.extra, PRUNED_TOPOHEIGHT)?;
                self.pruned_topoheight = None;

                break 'main;
            }

            topoheight -= 1;
            // height of old block become new height
            if block.get_height() < height {
                height = block.get_height();
            }
            done += 1;
        }

        debug!("Blocks processed {}, new topoheight: {}, new height: {}, tips: {}", done, topoheight, height, tips.len());

        trace!("Cleaning assets");

        // All deleted assets
        let mut deleted_assets = HashSet::new();
        
        // clean all assets
        for el in self.assets.iter() {
            let (key, value) = el.context("error on asset iterator")?;
            let asset = Hash::from_bytes(&key)?;
            trace!("verifying asset registered: {}", asset);

            let registration_topoheight = TopoHeight::from_bytes(&value)?;
            if registration_topoheight > topoheight {
                trace!("Asset {} was registered at topoheight {}, deleting", asset, registration_topoheight);
                // Delete it from registered assets
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.assets, &key)
                    .context(format!("Error while deleting asset {asset} from registered assets"))?;

                // drop the tree for this asset
                Self::drop_tree(self.snapshot.as_mut(), &self.db, key).context(format!("error on dropping asset {asset} tree"))?;

                deleted_assets.insert(asset);
            }
        }

        trace!("Cleaning nonces");
        // now let's process nonces versions
        // we set the new highest topoheight to the highest found under the new topoheight
        for el in self.nonces.iter() {
            let (key, value) = el?;
            let highest_topoheight = TopoHeight::from_bytes(&value)?;
            if highest_topoheight < pruned_topoheight {
                warn!("wrong nonce topoheight stored, highest topoheight is {}, pruned topoheight is {}", highest_topoheight, pruned_topoheight);
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.nonces, &key)?;
                continue;
            }

            if highest_topoheight > topoheight {
                let contains = Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.nonces, &key)?;
                if contains {
                    self.store_accounts_count(self.count_accounts().await? - 1)?;
                }

                // find the first version which is under topoheight
                let pkey = PublicKey::from_bytes(&key)?;
                trace!("Highest topoheight for {} nonce is {}, above {}", pkey.as_address(self.is_mainnet()), highest_topoheight, topoheight);
                let mut version = self.get_nonce_at_exact_topoheight(&pkey, highest_topoheight).await
                    .context(format!("Error while retrieving nonce at exact topoheight {highest_topoheight}"))?;

                while let Some(previous_topoheight) = version.get_previous_topoheight() {
                    if previous_topoheight <= topoheight {
                        // we find the new highest version which is under new topoheight
                        trace!("New highest version nonce for {} is at topoheight {}", pkey.as_address(self.is_mainnet()), previous_topoheight);
                        let insert = Self::insert_into_disk(self.snapshot.as_mut(), &self.nonces, &key, &previous_topoheight.to_be_bytes())?;
                        if insert.is_none() {
                            self.store_accounts_count(self.count_accounts().await? + 1)?;
                        }
                        break;
                    }

                    // keep searching
                    version = self.get_nonce_at_exact_topoheight(&pkey, previous_topoheight).await
                        .context(format!("Error while searching nonce at exact topoheight"))?;
                }
            } else {
                // nothing to do as its under the rewinded topoheight
            }
        }

        trace!("Cleaning balances");
        // do balances too
        for el in self.balances.iter() {
            let (key, value) = el?;
            let asset = Hash::from_bytes(&key[32..64])?;
            let mut delete = false;

            // if the asset is not deleted, we can process it
            if !deleted_assets.contains(&asset) {
                let highest_topoheight = u64::from_bytes(&value)?;
                if highest_topoheight > topoheight && highest_topoheight >= pruned_topoheight {
                    // find the first version which is under topoheight
                    let pkey = PublicKey::from_bytes(&key[0..32])?;
                    trace!("Highest topoheight for balance {} is {}, above {}", pkey.as_address(self.is_mainnet()), highest_topoheight, topoheight);

                    let mut version = self.get_balance_at_exact_topoheight(&pkey, &asset, highest_topoheight).await
                        .context(format!("Error while retrieving balance at exact topoheight {highest_topoheight}"))?;

                    // Mark for deletion if we can't find a version under the new topoheight
                    delete = true;

                    while let Some(previous_topoheight) = version.get_previous_topoheight() {
                        if previous_topoheight <= topoheight {
                            // we find the new highest version which is under new topoheight
                            trace!("New highest version balance for {} is at topoheight {} with asset {}", pkey.as_address(self.is_mainnet()), previous_topoheight, asset);
                            Self::insert_into_disk(self.snapshot.as_mut(), &self.balances, &key, &previous_topoheight.to_be_bytes())?;
                            delete = false;
                            break;
                        }
    
                        // keep searching
                        version = self.get_balance_at_exact_topoheight(&pkey, &asset, previous_topoheight).await?;
                    }
                }
            } else {
                delete = true;
            }

            if delete {
                Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.balances, &key)?;
            }
        }

        warn!("Blocks rewinded: {}, new topoheight: {}, new height: {}", done, topoheight, height);

        trace!("Cleaning versioned balances and nonces");

        // now delete all versioned balances and nonces above the new topoheight
        self.delete_versioned_data_above_topoheight(topoheight).await?;

        trace!("Cleaning caches");
        // Clear all caches to not have old data after rewind
        self.clear_caches().await?;

        trace!("Storing new pointers");
        // store the new tips and topo topoheight
        self.store_tips(&tips)?;
        self.set_top_topoheight(topoheight)?;
        self.set_top_height(height)?;

        // Reduce the count of blocks stored
        let count = self.count_blocks().await? - done;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, BLOCKS_COUNT, &count.to_be_bytes())?;

        Ok((height, topoheight, txs))
    }

    async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        trace!("get top block hash");
        self.get_hash_at_topo_height(self.get_top_topoheight()?).await
    }

    fn get_top_topoheight(&self) -> Result<TopoHeight, BlockchainError> {
        trace!("get top topoheight");
        self.load_from_disk(&self.extra, TOP_TOPO_HEIGHT, DiskContext::TopTopoHeight)
    }

    fn set_top_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set new top topoheight at {}", topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, TOP_TOPO_HEIGHT, &topoheight.to_be_bytes())?;
        Ok(())
    }

    fn get_top_height(&self) -> Result<u64, BlockchainError> {
        trace!("get top height");
        self.load_from_disk(&self.extra, TOP_HEIGHT, DiskContext::TopHeight)
    }

    fn set_top_height(&mut self, height: u64) -> Result<(), BlockchainError> {
        trace!("set new top height at {}", height);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, TOP_HEIGHT, &height.to_be_bytes())?;
        Ok(())
    }

    async fn get_top_block_header(&self) -> Result<(Arc<BlockHeader>, Hash), BlockchainError> {
        trace!("get top block header");
        let hash = self.get_top_block_hash().await?;
        Ok((self.get_block_header_by_hash(&hash).await?, hash))
    }

    async fn get_top_block(&self) -> Result<Block, BlockchainError> {
        trace!("get top block");
        let (block, _) = self.get_top_block_header().await?;
        let mut transactions = Vec::new();
        for tx in block.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let block = Block::new(Immutable::Arc(block), transactions);
        Ok(block)
    }

    // Returns the current size on disk in bytes
    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError> {
        Ok(self.db.size_on_disk()?)
    }

    async fn stop(&mut self) -> Result<(), BlockchainError> {
        info!("Stopping Storage...");
        info!("Flushing Sled database");
        self.db.flush_async().await?;
        info!("Sled database flushed");
        Ok(())
    }

    async fn get_unexecuted_transactions(&self) -> Result<IndexSet<Hash>, BlockchainError> {
        trace!("get unexecuted transactions");
        let mut txs = IndexSet::new();
        for el in self.transactions.iter().keys() {
            let key = el?;
            let tx_hash = Hash::from_bytes(&key)?;
            if !self.is_tx_executed_in_a_block(&tx_hash)? {
                txs.insert(tx_hash);
            }
        }

        Ok(txs)
    }
}