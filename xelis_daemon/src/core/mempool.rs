use super::{
    blockchain::Blockchain,
    error::BlockchainError,
    storage::Storage
};
use std::{collections::HashMap, mem};
use std::sync::Arc;
use indexmap::IndexSet;
use log::{trace, debug, warn};
use xelis_common::{
    account::VersionedBalance,
    time::{TimestampSeconds, get_current_time_in_seconds},
    crypto::{
        Hash,
        PublicKey
    },
    transaction::Transaction
};

// Wrap a TX with its hash and size in bytes for faster access
// size of tx can be heavy to compute, so we store it here
#[derive(serde::Serialize)]
pub struct SortedTx {
    tx: Arc<Transaction>,
    first_seen: TimestampSeconds, // timestamp when the tx was added
    size: usize
}

// This struct is used to keep nonce cache for a specific key for faster verification
// But we also include a sorted list of txs for this key, ordered by nonce
// and a "expected balance" for this key
// Min/max bounds are used to compute the index of the tx in the sorted list based on its nonce
// You can get the TX at nonce N by computing the index with (N - min) % (max + 1 - min)
#[derive(serde::Serialize)]
pub struct AccountCache {
    // lowest nonce used
    min: u64,
    // highest nonce used
    max: u64,
    // all txs for this user ordered by nonce
    txs: IndexSet<Arc<Hash>>,
    // Expected balances after all txs in this cache
    // This is also used to verify the validity of the TX spendings
    balances: HashMap<Hash, VersionedBalance>
}

#[derive(serde::Serialize)]
pub struct Mempool {
    // store all txs waiting to be included in a block
    txs: HashMap<Arc<Hash>, SortedTx>,
    // store all sender's nonce for faster finding
    caches: HashMap<PublicKey, AccountCache>
}

impl Mempool {
    // Create a new empty mempool
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
            caches: HashMap::new()
        }
    }

    // All checks are made in Blockchain before calling this function
    pub fn add_tx(&mut self, hash: Hash, tx: Arc<Transaction>, size: usize, balances: HashMap<Hash, VersionedBalance>) -> Result<(), BlockchainError> {
        let hash = Arc::new(hash);
        let nonce = tx.get_nonce();
        // update the cache for this owner
        let mut must_update = true;
        if let Some(cache) = self.caches.get_mut(tx.get_owner()) {
            // delete the TX if its in the range of already tracked nonces
            trace!("Cache found for owner {} with nonce range {}-{}, nonce = {}", tx.get_owner(), cache.get_min(), cache.get_max(), nonce);

            // Support the case where the nonce is already used in cache
            // If a user want to cancel its TX, he can just resend a TX with same nonce and higher fee
            // NOTE: This is not possible anymore, disabled in blockchain function
            if nonce >= cache.get_min() && nonce <= cache.get_max() {
                trace!("nonce {} is in range {}-{}", nonce, cache.get_min(), cache.get_max());
                // because it's based on order and we may have the same order
                let index = ((nonce - cache.get_min()) % (cache.get_max() + 1 - cache.get_min())) as usize;
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
            // Update re-computed balances
            cache.set_balances(balances);
        } else {
            let mut txs = IndexSet::new();
            txs.insert(hash.clone());

            // init the cache
            let cache = AccountCache {
                max: nonce,
                min: nonce,
                txs,
                balances
            };
            self.caches.insert(tx.get_owner().clone(), cache);
        }

        let sorted_tx = SortedTx {
            size,
            first_seen: get_current_time_in_seconds(),
            tx
        };

        // insert in map
        self.txs.insert(hash, sorted_tx);

        Ok(())
    }

    // Remove a TX using its hash from mempool
    // This will recalculate the cache bounds
    pub fn remove_tx(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        let tx = self.txs.remove(hash).ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
        // remove the tx hash from sorted txs
        let key = tx.get_tx().get_owner();
        let mut delete = false;
        if let Some(cache) = self.caches.get_mut(key) {
            // Shift remove is O(n) on average, but we need to preserve the order
            if !cache.txs.shift_remove(hash) {
                warn!("TX {} not found in mempool while deleting", hash);
            } else {
                trace!("TX {} removed from cache", hash);
                delete = cache.txs.is_empty();
                if !delete {
                    trace!("Updating cache bounds");
                    let mut max: Option<u64> = None;
                    let mut min: Option<u64> = None;
                    // Update cache bounds
                    for tx_hash in cache.txs.iter() {
                        let tx = self.txs.get(tx_hash).ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
                        let nonce = tx.get_tx().get_nonce();
    
                        // Update cache highest bounds
                        if let Some(v) = max.clone() {
                            if  v < nonce {
                                max = Some(nonce);
                            }
                        } else {
                            max = Some(nonce);
                        }
    
                        // Update cache lowest bounds
                        if let Some(v) = min.clone() {
                            if  v > nonce {
                                min = Some(nonce);
                            }
                        } else {
                            min = Some(nonce);
                        }
                    }
    
                    if let (Some(min), Some(max)) = (min, max) {
                        trace!("Updating cache bounds to {}-{}", min, max);
                        cache.min = min;
                        cache.max = max;
                    }
                }
            }
        } else {
            warn!("No cache found for owner {} while deleting TX {}", tx.get_tx().get_owner(), hash);
        }

        if delete {
            trace!("Removing empty nonce cache for owner {}", key);
            self.caches.remove(key);
        }

        Ok(())
    }

    // Get the nonce cache for all keys
    pub fn get_caches(&self) -> &HashMap<PublicKey, AccountCache> {
        &self.caches
    }

    // Verify if a TX is in mempool using its hash
    pub fn contains_tx(&self, hash: &Hash) -> bool {
        self.txs.contains_key(hash)
    }

    // Get a sorted TX from its hash
    // This is useful to get its size along the TX and its first seen
    pub fn get_sorted_tx(&self, hash: &Hash) -> Result<&SortedTx, BlockchainError> {
        let tx = self.txs.get(hash).ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
        Ok(tx)
    }

    // Get a TX (cloned) from mempool using its hash
    pub fn get_tx(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        let tx = self.get_sorted_tx(hash)?;
        Ok(Arc::clone(tx.get_tx()))
    }

    // Get a reference of TX from mempool using its hash
    pub fn view_tx<'a>(&'a self, hash: &Hash) -> Result<&'a Arc<Transaction>, BlockchainError> {
        if let Some(sorted_tx) = self.txs.get(hash) {
            return Ok(sorted_tx.get_tx())
        }

        Err(BlockchainError::TxNotFound(hash.clone()))
    }

    // Get all txs in mempool
    pub fn get_txs(&self) -> &HashMap<Arc<Hash>, SortedTx> {
        &self.txs
    }

    // Get the cache for a specific key
    pub fn get_cache_for(&self, key: &PublicKey) -> Option<&AccountCache> {
        self.caches.get(key)
    }

    // Check if the nonce is already used for user in mempool
    pub fn is_nonce_used(&self, key: &PublicKey, nonce: u64) -> bool {
        if let Some(cache) = self.caches.get(key) {
            if nonce >= cache.min && nonce <= cache.max {
                return cache.has_tx_with_same_nonce(nonce).is_some();
            }
        }

        false
    }

    // Returns the count of txs in mempool
    pub fn size(&self) -> usize {
        self.txs.len()
    }

    // Clear all txs and caches in mempool
    pub fn clear(&mut self) {
        self.txs.clear();
        self.caches.clear();
    }

    // delete all old txs not compatible anymore with current state of chain
    // this is called when a new block is added to the chain
    // Because of DAG reorg, we can't only check updated keys from new block,
    // as a block could be orphaned and the nonce order would change
    // So we need to check all keys from mempool and compare it from storage
    pub async fn clean_up<S: Storage>(&mut self, storage: &S, blockchain: &Blockchain<S>, topoheight: u64) {
        trace!("Cleaning up mempool...");

        let mut cache = HashMap::new();
        // Swap the nonces_cache with cache, so we iterate over cache and reinject it in nonces_cache
        std::mem::swap(&mut cache, &mut self.caches);

        for (key, mut cache) in cache {
            let nonce = match storage.get_last_nonce(&key).await {
                Ok((_, version)) => version.get_nonce(),
                Err(e) => {
                    // We get an error while retrieving the last nonce for this key,
                    // that means the key is not in storage anymore, so we can delete safely
                    // we just have to skip this iteration so it's not getting re-injected
                    debug!("Error while getting nonce for owner {}, he maybe has no nonce anymore, skipping: {}", key, e);
                    continue;
                }
            };

            let mut delete_cache = false;
            // Check if the minimum nonce is higher than the new nonce, that means
            // all TXs will be orphaned as its suite got broken
            // or, check and delete txs if the nonce is lower than the new nonce
            // otherwise the cache is still up to date
            if cache.get_min() > nonce {
                trace!("All TXs for key {} are orphaned, deleting them", key);
                // We can delete all these TXs as they got automatically orphaned
                // Because of the suite being broked
                for hash in cache.txs.iter() {
                    if self.txs.remove(hash).is_none() {
                        warn!("TX {} not found in mempool while deleting", hash);
                    }
                }
                delete_cache = true;
            } else if cache.get_min() < nonce {
                trace!("Deleting TXs for owner {} with nonce < {}", key, nonce);
                // txs hashes to delete
                let mut hashes: Vec<Arc<Hash>> = Vec::with_capacity(cache.txs.len());

                // filter all txs hashes which are not found
                // or where its nonce is smaller than the new nonce
                // TODO when drain_filter is stable, use it (allow to get all hashes deleted)
                let mut max: Option<u64> = None;
                let mut min: Option<u64> = None;
                cache.txs.retain(|hash| {
                    let mut delete = true;

                    if let Some(tx) = self.txs.get(hash) {
                        let tx_nonce = tx.get_tx().get_nonce();
                        // If TX is still compatible with new nonce, update bounds
                        if tx_nonce >= nonce {
                            // Update cache highest bounds
                            if let Some(v) = max.clone() {
                                if  v < tx_nonce {
                                    max = Some(tx_nonce);
                                }
                            } else {
                                max = Some(tx_nonce);
                            }

                            // Update cache lowest bounds
                            if let Some(v) = min.clone() {
                                if  v > tx_nonce {
                                    min = Some(tx_nonce);
                                }
                            } else {
                                min = Some(tx_nonce);
                            }
                            delete = false;
                        }
                    }

                    // Add hash in list if we delete it
                    if delete {
                        hashes.push(Arc::clone(hash));
                    }
                    !delete
                });

                // Update cache bounds
                if let (Some(min), Some(max)) = (min, max) {
                    debug!("Update cache bounds: [{}-{}]", min, max);
                    cache.min = min;
                    cache.max = max;
                }

                // delete the nonce cache if no txs are left
                delete_cache = cache.txs.is_empty();
                // Cache is not empty yet, but we deleted some TXs from it, balances may be out-dated, verify TXs left
                // TODO: there may be a way to optimize this even more, by checking if deleted TXs are those who got mined
                // Which mean, expected balances are still up to date with chain state
                if !delete_cache && !hashes.is_empty() {
                    let mut balances = HashMap::new();
                    let mut invalid_txs = Vec::new();
                    for tx_hash in &cache.txs {
                        if let Some(sorted_tx) = self.txs.get(tx_hash) {
                            // Verify if the TX is still valid
                            // If not, delete it
                            let tx = sorted_tx.get_tx();

                            // Skip nonces verification as we already did it
                            if let Err(e) = blockchain.verify_transaction_with_hash(storage, tx, &tx_hash, &mut balances, None, true, topoheight).await {
                                warn!("TX {} is not valid anymore, deleting it: {}", tx_hash, e);
                                // Clone is needed as we can't remove a value from a map while iterating over it
                                invalid_txs.push(tx_hash.clone());
                            }
                        } else {
                            // Shouldn't happen
                            warn!("TX {} not found in mempool while verifying", tx_hash);
                        }
                    }

                    // Update balances cache
                    if let Some(balances) = balances.remove(&key) {
                        cache.set_balances(balances.into_iter().map(|(k, v)| (k.clone(), v)).collect());
                    }

                    if invalid_txs.len() == cache.txs.len() {
                        // All txs are invalid, delete the cache
                        delete_cache = true;

                        // We empty the cache, so we can delete all txs
                        let mut local_cache = IndexSet::new();
                        mem::swap(&mut local_cache, &mut cache.txs);

                        hashes.extend(local_cache);
                    } else {
                        // Delete all invalid txs from cache
                        for hash in invalid_txs {
                            // We have to shift remove as we need to preserve the order
                            // This in O(n) on average
                            cache.txs.shift_remove(&hash);
                            hashes.push(hash);
                        }
                    }

                }

                // now delete all necessary txs
                for hash in hashes {
                    if self.txs.remove(&hash).is_none() {
                        warn!("TX {} not found in mempool while deleting", hash);
                    }
                }
            }

            if !delete_cache {
                debug!("Re-injecting nonce cache for owner {}", key);
                self.caches.insert(key, cache);
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

    pub fn get_first_seen(&self) -> TimestampSeconds {
        self.first_seen
    }

    pub fn consume(self) -> Arc<Transaction> {
        self.tx
    }
}

impl AccountCache {
    // Get the lowest nonce for this cache
    pub fn get_min(&self) -> u64 {
        self.min
    }

    // Get the highest nonce for this cache
    pub fn get_max(&self) -> u64 {
        self.max
    }

    // Get all txs hashes for this cache
    pub fn get_txs(&self) -> &IndexSet<Arc<Hash>> {
        &self.txs
    }

    // Update balances cache
    fn set_balances(&mut self, balances: HashMap<Hash, VersionedBalance>) {
        self.balances = balances;
    }

    // Returns the expected balances cache after the execution of all TXs
    pub fn get_balances(&self) -> &HashMap<Hash, VersionedBalance> {
        &self.balances
    }

    // Update the cache with a new TX
    fn update(&mut self, nonce: u64, hash: Arc<Hash>) {
        self.update_nonce_range(nonce);
        self.txs.insert(hash);
    }

    // Update the nonce range for this cache
    fn update_nonce_range(&mut self, nonce: u64) {
        debug_assert!(self.min <= self.max);

        if nonce < self.min {
            self.min = nonce;
        }

        if nonce > self.max {
            self.max = nonce;
        }
    }

    // Verify if a TX is in cache using its nonce
    pub fn has_tx_with_same_nonce(&self, nonce: u64) -> Option<&Arc<Hash>> {
        if nonce < self.min || nonce > self.max || self.txs.is_empty() {
            return None;
        }

        trace!("has tx with same nonce: {}, max: {}, min: {}, size: {}", nonce, self.max, self.min, self.txs.len());
        let index = ((nonce - self.min) % (self.max + 1 - self.min)) as usize;
        self.txs.get_index(index)
    }
}