use std::ops::{Deref, DerefMut};

use xelis_common::block::TopoHeight;

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

#[derive(Debug, Default, Clone)]
pub struct StorageCache {
    counter: CounterCache,

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