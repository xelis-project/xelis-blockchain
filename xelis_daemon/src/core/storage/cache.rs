use std::{
    collections::HashSet,
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    sync::Arc
};

use indexmap::IndexSet;
use lru::LruCache;
use xelis_common::{
    tokio::sync::Mutex,
    block::{BlockHeader, TopoHeight},
    crypto::Hash,
    difficulty::{CumulativeDifficulty, Difficulty},
    transaction::Transaction
};

use crate::config::{DEFAULT_CACHE_SIZE, GENESIS_BLOCK_DIFFICULTY};

use super::Tips;

// GHOSTDAG data for incremental computation
#[derive(Debug, Clone)]
pub struct GhostDagData {
    pub cumulative_difficulty: CumulativeDifficulty,
    pub selected_parent: Option<Hash>,
    pub merge_set_blues: HashSet<Hash>,
}

#[macro_export]
macro_rules! init_cache {
    ($cache_size: expr) => {{
        Mutex::new(LruCache::new(NonZeroUsize::new($cache_size).expect("Non zero value for cache")))
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

#[derive(Debug)]
pub struct ChainCache {
    // this cache is used to avoid to recompute the common base for each block and is mandatory
    // key is (tip hash, tip height) while value is (base hash, base height)
    pub tip_base_cache: Mutex<LruCache<(Hash, u64), (Hash, u64)>>,
    // This cache is used to avoid to recompute the common base
    // key is a combined hash of tips
    pub common_base_cache: Mutex<LruCache<Hash, (Hash, u64)>>,
    // tip work score is used to determine the best tip based on a block, tip base ands a base height
    pub tip_work_score_cache: Mutex<LruCache<(Hash, Hash, u64), (HashSet<Hash>, CumulativeDifficulty)>>,
    // using base hash, current tip hash and base height, this cache is used to store the DAG order
    pub full_order_cache: Mutex<LruCache<(Hash, Hash, u64), IndexSet<Hash>>>,
    // blue set cache for GHOSTDAG
    pub blue_set_cache: Mutex<LruCache<(Hash, TopoHeight), HashSet<Hash>>>,
    // GHOSTDAG data cache (incremental computation)
    pub ghost_dag_cache: Mutex<LruCache<Hash, Arc<GhostDagData>>>,
    // current difficulty at tips
    // its used as cache to display current network hashrate
    pub difficulty: Difficulty,
    // current block height
    pub height: u64,
    // current topo height
    pub topoheight: TopoHeight,
    // current stable height
    pub stable_height: u64,
    // Determine which last block is stable
    // It is used mostly for chain rewind limit
    pub stable_topoheight: TopoHeight,
    // current tips of the chain
    pub tips: Tips,
}

impl ChainCache {
    pub fn clear_caches(&mut self) {
        self.tip_base_cache.get_mut().clear();
        self.common_base_cache.get_mut().clear();
        self.tip_work_score_cache.get_mut().clear();
        self.full_order_cache.get_mut().clear();
    }

    pub fn clone_mut(&mut self) -> Self {
        Self {
            tip_base_cache: Mutex::new(self.tip_base_cache.get_mut().clone()),
            common_base_cache: Mutex::new(self.common_base_cache.get_mut().clone()),
            tip_work_score_cache: Mutex::new(self.tip_work_score_cache.get_mut().clone()),
            full_order_cache: Mutex::new(self.full_order_cache.get_mut().clone()),
            blue_set_cache: Mutex::new(self.blue_set_cache.get_mut().clone()),
            ghost_dag_cache: Mutex::new(self.ghost_dag_cache.get_mut().clone()),
            height: self.height,
            topoheight: self.topoheight,
            stable_height: self.stable_height,
            stable_topoheight: self.stable_topoheight,
            difficulty: self.difficulty.clone(),
            tips: self.tips.clone(),
        }
    }
}

impl Default for ChainCache {
    fn default() -> Self {
        Self {
            tip_base_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).expect("Default cache size for tip base must be above 0"))),
            tip_work_score_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).expect("Default cache size for tip work score must be above 0"))),
            common_base_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).expect("Default cache size for common base must be above 0"))),
            full_order_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).expect("Default cache size for full order must be above 0"))),
            blue_set_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).expect("Default cache size for blue set must be above 0"))),
            ghost_dag_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).expect("Default cache size for ghost dag must be above 0"))),
            height: 0,
            topoheight: 0,
            stable_height: 0,
            stable_topoheight: 0,
            difficulty: GENESIS_BLOCK_DIFFICULTY,
            tips: Tips::default(),
        }
    }
}

#[derive(Debug)]
pub struct ObjectsCache {
    // Transaction cache
    pub transactions_cache: Mutex<LruCache<Hash, Arc<Transaction>>>,
    // Block header cache
    pub blocks_cache: Mutex<LruCache<Hash, Arc<BlockHeader>>>,
    // Topoheight by hash cache
    pub topo_by_hash_cache: Mutex<LruCache<Hash, TopoHeight>>,
    // Hash by topoheight cache
    pub hash_at_topo_cache: Mutex<LruCache<TopoHeight, Hash>>,
    // Cumulative difficulty cache
    pub cumulative_difficulty_cache: Mutex<LruCache<Hash, CumulativeDifficulty>>,
    // Assets cache
    pub assets_cache: Mutex<LruCache<Hash, TopoHeight>>,
}

impl ObjectsCache {
    pub fn new(cache_size: usize) -> Self {
        Self {
            transactions_cache: init_cache!(cache_size),
            blocks_cache: init_cache!(cache_size),
            topo_by_hash_cache: init_cache!(cache_size),
            hash_at_topo_cache: init_cache!(cache_size),
            cumulative_difficulty_cache: init_cache!(cache_size),
            assets_cache: init_cache!(cache_size),
        }
    }

    pub fn clone_mut(&mut self) -> Self {
        Self {
            transactions_cache: Mutex::new(self.transactions_cache.get_mut().clone()),
            blocks_cache: Mutex::new(self.blocks_cache.get_mut().clone()),
            topo_by_hash_cache: Mutex::new(self.topo_by_hash_cache.get_mut().clone()),
            hash_at_topo_cache: Mutex::new(self.hash_at_topo_cache.get_mut().clone()),
            cumulative_difficulty_cache: Mutex::new(self.cumulative_difficulty_cache.get_mut().clone()),
            assets_cache: Mutex::new(self.assets_cache.get_mut().clone()),
        }
    }

    pub fn clear_caches(&mut self) {
        self.transactions_cache.get_mut().clear();
        self.blocks_cache.get_mut().clear();
        self.topo_by_hash_cache.get_mut().clear();
        self.hash_at_topo_cache.get_mut().clear();
        self.cumulative_difficulty_cache.get_mut().clear();
        self.assets_cache.get_mut().clear();
    }
}

// Storage cache contains all our needed caches
// During a clone, only the counters are cloned
#[derive(Debug, Default)]
pub struct StorageCache {
    pub counter: CounterCache,
    pub chain: ChainCache,

    // all available caches
    pub objects: Option<ObjectsCache>,

    // At which size all caches were initialized
    pub cache_size: Option<usize>,
}

impl StorageCache {
    pub fn new(cache_size: Option<usize>) -> Self {
        Self {
            counter: CounterCache::default(),
            chain: ChainCache::default(),
            objects: cache_size.map(ObjectsCache::new),
            cache_size
        }
    }

    pub fn clear_caches(&mut self) {
        self.chain.clear_caches();
        if let Some(objects) = &mut self.objects {
            objects.clear_caches();
        }
    }

    pub fn clone_mut(&mut self) -> Self {
        Self {
            counter: self.counter.clone(),
            chain: self.chain.clone_mut(),
            objects: self.objects.as_mut().map(|v| v.clone_mut()),
            cache_size: self.cache_size
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