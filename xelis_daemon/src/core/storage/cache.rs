use std::{ops::{Deref, DerefMut}, sync::Arc};

use indexmap::IndexSet;
use lru::LruCache;
use tokio::sync::Mutex;
use xelis_common::{
    block::{BlockHeader, TopoHeight},
    crypto::Hash,
    difficulty::CumulativeDifficulty,
    transaction::Transaction
};

use super::Tips;

#[macro_export]
macro_rules! init_cache {
    ($cache_size: expr) => {{
        if let Some(size) = &$cache_size {
            Some(Mutex::new(LruCache::new(std::num::NonZeroUsize::new(*size).expect("Non zero value for cache"))))
        } else {
            None
        }
    }};
}

#[derive(Debug, Default, Clone)]
pub struct CounterCache {
    // Count of assets
    pub assets_count: u64,
    // Count of accounts
    pub accounts_count: u64,
    // Count of transactions
    pub transactions_count: u64,
    // Count of blocks
    pub blocks_count: u64,
    // Count of blocks added in chain
    pub blocks_execution_count: u64,
    // Count of contracts
    pub contracts_count: u64,
    // Tips cache
    pub tips_cache: Tips,
    // Pruned topoheight cache
    pub pruned_topoheight: Option<TopoHeight>,
}

// Storage cache contains all our needed caches
// During a clone, only the counters are cloned
#[derive(Debug, Default)]
pub struct StorageCache {
    pub counter: CounterCache,

    // all available caches
    // Transaction cache
    pub transactions_cache: Option<Mutex<LruCache<Hash, Arc<Transaction>>>>,
    // Block header cache
    pub blocks_cache: Option<Mutex<LruCache<Hash, Arc<BlockHeader>>>>,
    // Blocks Tips cache
    pub past_blocks_cache: Option<Mutex<LruCache<Hash, Arc<IndexSet<Hash>>>>>,
    // Topoheight by hash cache
    pub topo_by_hash_cache: Option<Mutex<LruCache<Hash, TopoHeight>>>,
    // Hash by topoheight cache
    pub hash_at_topo_cache: Option<Mutex<LruCache<TopoHeight, Hash>>>,
    // Cumulative difficulty cache
    pub cumulative_difficulty_cache: Option<Mutex<LruCache<Hash, CumulativeDifficulty>>>,
    // Assets cache
    pub assets_cache: Option<Mutex<LruCache<Hash, TopoHeight>>>,

    // At which size all caches were initialized
    pub cache_size: Option<usize>,
}

impl StorageCache {
    pub fn new(cache_size: Option<usize>) -> Self {
        Self {
            counter: CounterCache::default(),
            transactions_cache: init_cache!(cache_size),
            blocks_cache: init_cache!(cache_size),
            past_blocks_cache: init_cache!(cache_size),
            topo_by_hash_cache: init_cache!(cache_size),
            hash_at_topo_cache: init_cache!(cache_size),
            cumulative_difficulty_cache: init_cache!(cache_size),
            assets_cache: init_cache!(cache_size),
            cache_size
        }
    }
}

impl Clone for StorageCache {
    fn clone(&self) -> Self {
        Self {
            counter: self.counter.clone(),
            ..Default::default()
        }
    }
}

impl Deref for StorageCache {
    type Target = CounterCache;

    fn deref(&self) -> &Self::Target {
        &self.counter
    }
}

impl DerefMut for StorageCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.counter
    }
}