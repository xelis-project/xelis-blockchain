use super::error::BlockchainError;
use std::collections::HashMap;
use std::sync::Arc;
use indexmap::IndexSet;
use log::{trace, debug, warn};
use xelis_common::utils::get_current_time;
use xelis_common::{
    crypto::{
        hash::Hash,
        key::PublicKey
    },
    transaction::Transaction,
    serializer::Serializer
};

#[derive(serde::Serialize)]
pub struct SortedTx {
    tx: Arc<Transaction>,
    first_seen: u64, // timestamp when the tx was added
    size: usize
}

#[derive(serde::Serialize)]
pub struct NonceCache {
    min: u64,
    max: u64,
    // all txs for this user ordered by nonce
    txs: IndexSet<Arc<Hash>>,
}

#[derive(serde::Serialize)]
pub struct Mempool {
    // store all txs waiting to be included in a block
    txs: HashMap<Arc<Hash>, SortedTx>,
    // store all sender's nonce for faster finding
    nonces_cache: HashMap<PublicKey, NonceCache>
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
            nonces_cache: HashMap::new()
        }
    }

    // All checks are made in Blockchain before calling this function
    pub fn add_tx(&mut self, hash: Hash, tx: Arc<Transaction>) -> Result<(), BlockchainError> {
        let hash = Arc::new(hash);
        let nonce = tx.get_nonce();
        // update the cache for this owner
        let mut must_update = true;
        if let Some(cache) = self.nonces_cache.get_mut(tx.get_owner()) {
            // delete the TX if its in the range of already tracked nonces
            trace!("Cache found for owner {} with nonce range {}-{}, nonce = {}", tx.get_owner(), cache.get_min(), cache.get_max(), nonce);
            if nonce >= cache.get_min() && nonce <= cache.get_max() {
                trace!("nonce {} is in range {}-{}", nonce, cache.get_min(), cache.get_max());
                // because it's based on order and we may have the same order
                let index = ((nonce - cache.get_min()) % (cache.get_max() - cache.get_min())) as usize;
                cache.txs.insert(hash.clone());
                must_update = false;

                if let Some(tx_hash) = cache.txs.swap_remove_index(index) {
                    trace!("TX {} with same nonce found in cache, removing it from sorted txs", tx_hash);
                    // remove the tx hash from sorted txs
                    if self.txs.remove(&tx_hash).is_none() {
                        warn!("TX {} not found in mempool while deleting collision with {}", tx_hash, hash);
                    }
                } else {
                    warn!("No TX found in cache for nonce {} while adding {}", nonce, hash);
                }
            }

            if must_update {
                cache.update(nonce, hash.clone());
            }
        } else {
            let mut txs = IndexSet::new();
            txs.insert(hash.clone());

            // init the cache
            let cache = NonceCache {
                max: nonce,
                min: nonce,
                txs
            };
            self.nonces_cache.insert(tx.get_owner().clone(), cache);
        }

        let sorted_tx = SortedTx {
            size: tx.size(),
            first_seen: get_current_time(),
            tx
        };

        // insert in map
        self.txs.insert(hash, sorted_tx);

        Ok(())
    }

    pub fn get_nonces_cache(&self) -> &HashMap<PublicKey, NonceCache> {
        &self.nonces_cache
    }

    pub fn contains_tx(&self, hash: &Hash) -> bool {
        self.txs.contains_key(hash)
    }

    pub fn get_sorted_tx(&self, hash: &Hash) -> Result<&SortedTx, BlockchainError> {
        let tx = self.txs.get(hash).ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
        Ok(tx)
    }

    pub fn get_tx(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        let tx = self.get_sorted_tx(hash)?;
        Ok(Arc::clone(tx.get_tx()))
    }

    pub fn view_tx<'a>(&'a self, hash: &Hash) -> Result<&'a Arc<Transaction>, BlockchainError> {
        if let Some(sorted_tx) = self.txs.get(hash) {
            return Ok(sorted_tx.get_tx())
        }

        Err(BlockchainError::TxNotFound(hash.clone()))
    }

    pub fn get_txs(&self) -> &HashMap<Arc<Hash>, SortedTx> {
        &self.txs
    }

    pub fn get_cached_nonce(&self, key: &PublicKey) -> Option<&NonceCache> {
        self.nonces_cache.get(key)
    }

    pub fn size(&self) -> usize {
        self.txs.len()
    }

    pub fn clear(&mut self) {
        self.txs.clear();
        self.nonces_cache.clear();
    }

    // delete all old txs not compatible anymore with current state of account
    pub async fn clean_up(&mut self, nonces: HashMap<PublicKey, u64>) {
        if self.nonces_cache.is_empty() || nonces.is_empty() {
            debug!("No mempool cleanup needed");
            return;
        }

        debug!("Cleaning up mempool ({} accounts)...", nonces.len());
        for (key, nonce) in nonces {
            let mut delete_cache = false;
            // check if we have a TX in cache for this owner
            if let Some(cache) = self.nonces_cache.get_mut(&key) {
                // check if the minimum nonce used is lower than new nonce
                if cache.get_min() < nonce {
                    // txs hashes to delete
                    let mut hashes: Vec<Arc<Hash>> = Vec::with_capacity(cache.txs.len());

                    // filter all txs hashes which are not found
                    // or where its nonce is smaller than the new nonce
                    // TODO when drain_filter is stable, use it (allow to get all hashes deleted)
                    cache.txs.retain(|hash| {
                        let delete = if let Some(tx) = self.txs.get(hash) {
                            tx.get_tx().get_nonce() < nonce
                        } else {
                            true
                        };

                        if delete {
                            hashes.push(Arc::clone(hash));
                        }
                        !delete
                    });

                    // delete the nonce cache if no txs are left
                    delete_cache = cache.txs.is_empty();

                    // now delete all necessary txs
                    for hash in hashes {
                        if self.txs.remove(&hash).is_none() {
                            warn!("TX {} not found in mempool while deleting", hash);
                        }
                    }
                }
            }

            if delete_cache {
                trace!("Removing empty nonce cache for owner {}", key);
                self.nonces_cache.remove(&key);
            }
        }
    }
}

impl SortedTx {
    pub fn get_tx(&self) -> &Arc<Transaction> {
        &self.tx
    }

    pub fn get_fee(&self) -> u64 {
        self.tx.get_fee()
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn get_first_seen(&self) -> u64 {
        self.first_seen
    }

    pub fn consume(self) -> Arc<Transaction> {
        self.tx
    }
}

impl NonceCache {
    pub fn get_min(&self) -> u64 {
        self.min
    }

    pub fn get_max(&self) -> u64 {
        self.max
    }

    pub fn get_txs(&self) -> &IndexSet<Arc<Hash>> {
        &self.txs
    }

    fn update(&mut self, nonce: u64, hash: Arc<Hash>) {
        self.update_nonce_range(nonce);
        self.txs.insert(hash);
    }

    fn update_nonce_range(&mut self, nonce: u64) {
        debug_assert!(self.min <= self.max);

        if nonce < self.min {
            self.min = nonce;
        }

        if nonce > self.max {
            self.max = nonce;
        }
    }

    pub fn has_tx_with_same_nonce(&self, nonce: u64) -> Option<&Arc<Hash>> {
        if nonce < self.min || nonce > self.max || self.txs.is_empty() {
            return None;
        }

        trace!("has tx with same nonce: {}, max: {}, min: {}, size: {}", nonce, self.max, self.min, self.txs.len());
        let mut r = self.max - self.min;
        if r == 0 {
            r = self.txs.len() as u64;
        }

        let index = ((nonce - self.min) % r) as usize;
        self.txs.get_index(index)
    }
}