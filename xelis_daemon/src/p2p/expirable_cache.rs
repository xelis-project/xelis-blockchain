use std::{
    collections::HashMap,
    time::{Duration, Instant}
};
use xelis_common::{
    crypto::Hash,
    tokio::sync::Mutex
};

// Expirable cache used for requested objects (blocks, transactions)
// Used to keep tracking hashes requested to prevent false unrequested errors
pub struct ExpirableCache {
    cache: Mutex<HashMap<Hash, Instant>>
}

impl ExpirableCache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new())
        }
    }

    pub async fn insert(&self, hash: Hash) {
        let mut cache = self.cache.lock().await;
        cache.insert(hash, Instant::now());
    }

    pub async fn remove(&self, hash: &Hash) -> bool {
        let mut cache = self.cache.lock().await;
        cache.remove(hash).is_some()
    }

    pub async fn clean(&self, timeout: Duration) {
        let mut cache = self.cache.lock().await;
        cache.retain(|_, v| {
            v.elapsed() < timeout
        });
    }
}