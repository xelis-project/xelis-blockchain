use super::{
    error::BlockchainError,
    state::MempoolState,
    storage::Storage
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    mem,
};
use serde::{Serialize, Deserialize};
use indexmap::IndexSet;
use log::{debug, info, trace, warn};
use xelis_common::{
    config::{BYTES_PER_KB, FEE_PER_KB},
    account::Nonce,
    api::daemon::FeeRatesEstimated,
    block::{BlockVersion, TopoHeight},
    crypto::{
        elgamal::Ciphertext,
        Hash,
        PublicKey
    },
    network::Network,
    serializer::Serializer,
    time::{get_current_time_in_seconds, TimestampSeconds},
    transaction::{Transaction, MultiSigPayload}
};
use xelis_vm::Environment;

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
#[derive(Serialize, Deserialize)]
pub struct AccountCache {
    // lowest nonce used
    min: Nonce,
    // highest nonce used
    max: Nonce,
    // all txs for this user ordered by nonce
    txs: IndexSet<Arc<Hash>>,
    // Expected balances after all txs in this cache
    // This is also used to verify the validity of the TX spendings
    balances: HashMap<Hash, Ciphertext>,
    // Expected multisig after all txs in this cache
    multisig: Option<MultiSigPayload>
}

// Mempool is used to store all TXs waiting to be included in a block
// All TXs must be verified before adding them to the mempool
// Caches are used to store the nonce/order cache for each sender and their encrypted balances
// This is necessary to be fast enough to verify the TXs at each chain state change.
pub struct Mempool {
    // Used for log purpose
    mainnet: bool,
    // store all txs waiting to be included in a block
    txs: HashMap<Arc<Hash>, SortedTx>,
    // store all sender's nonce for faster finding
    caches: HashMap<PublicKey, AccountCache>
}

impl Mempool {
    // Create a new empty mempool
    pub fn new(network: Network) -> Self {
        Mempool {
            mainnet: network.is_mainnet(),
            txs: HashMap::new(),
            caches: HashMap::new()
        }
    }

    fn internal_estimate_fee_rates(mut fee_rates: Vec<u64>) -> FeeRatesEstimated {
        let len = fee_rates.len();
        // Top 30%
        let high_priority_count = len * 30 / 100;
        // Next 40%
        let normal_priority_count = len * 40 / 100;

        if len == 0 || high_priority_count == 0 || normal_priority_count == 0 {
            return FeeRatesEstimated {
                high: FEE_PER_KB,
                medium: FEE_PER_KB,
                low: FEE_PER_KB,
                default: FEE_PER_KB
            };
        }

        // Sort descending by fee rate
        fee_rates.sort_by(|a, b| b.cmp(a));

        let high: u64 = fee_rates[..high_priority_count]
            .iter()
            .sum::<u64>() / high_priority_count as u64;

        let medium: u64 = fee_rates[high_priority_count..(high_priority_count + normal_priority_count)]
            .iter()
            .sum::<u64>() / normal_priority_count as u64;

        let low: u64 = fee_rates[(high_priority_count + normal_priority_count)..]
            .iter()
            .sum::<u64>() / (len - high_priority_count - normal_priority_count) as u64;

        FeeRatesEstimated {
            high,
            medium,
            low,
            default: FEE_PER_KB
        }
    }

    // Find the fee per kB rate estimation for the priority levels
    // For this, we need to get the median fee rate for each priority level
    pub fn estimate_fee_rates(&self) -> Result<FeeRatesEstimated, BlockchainError> { 
        let fee_rates: Vec<_> = self.txs.values()
            .map(SortedTx::get_fee_rate_per_kb)
            .collect();

        Ok(Self::internal_estimate_fee_rates(fee_rates))
    }

    // All checks are made in Blockchain before calling this function
    pub async fn add_tx<S: Storage>(&mut self, storage: &S, environment: &Environment, stable_topoheight: TopoHeight, topoheight: TopoHeight, hash: Hash, tx: Arc<Transaction>, size: usize, block_version: BlockVersion) -> Result<(), BlockchainError> {
        let mut state = MempoolState::new(&self, storage, environment, stable_topoheight, topoheight, block_version, self.mainnet);
        tx.verify(&hash, &mut state).await?;

        let (balances, multisig) = state.get_sender_cache(tx.get_source())
            .ok_or_else(|| BlockchainError::AccountNotFound(tx.get_source().as_address(self.mainnet)))?;

        let balances = balances.into_iter().map(|(asset, ciphertext)| (asset.clone(), ciphertext)).collect();

        let hash = Arc::new(hash);
        let nonce = tx.get_nonce();
        // update the cache for this owner
        let mut must_update = true;
        if let Some(cache) = self.caches.get_mut(tx.get_source()) {
            // delete the TX if its in the range of already tracked nonces
            trace!("Cache found for owner {} with nonce range {}-{}, nonce = {}", tx.get_source().as_address(self.mainnet), cache.get_min(), cache.get_max(), nonce);

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
            cache.set_multisig(multisig);
        } else {
            let mut txs = IndexSet::new();
            txs.insert(hash.clone());

            // init the cache
            let cache = AccountCache {
                max: nonce,
                min: nonce,
                txs,
                balances,
                multisig
            };
            self.caches.insert(tx.get_source().clone(), cache);
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
        let key = tx.get_tx().get_source();
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
            warn!("No cache found for owner {} while deleting TX {}", tx.get_tx().get_source().as_address(self.mainnet), hash);
        }

        if delete {
            trace!("Removing empty nonce cache for owner {}", key.as_address(self.mainnet));
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

    // Drain all txs from mempool
    pub fn drain(&mut self) -> Vec<(Hash, Arc<Transaction>)> {
        let mut txs = Vec::with_capacity(self.txs.len());
        for (hash, sorted_tx) in self.txs.drain() {
            txs.push((hash.as_ref().clone(), sorted_tx.consume()));
        }

        self.caches.clear();

        txs
    }

    // delete all old txs not compatible anymore with current state of chain
    // this is called when a new block is added to the chain
    // Because of DAG reorg, we can't only check updated keys from new block,
    // as a block could be orphaned and the nonce order would change
    // So we need to check all keys from mempool and compare it from storage
    pub async fn clean_up<S: Storage>(&mut self, storage: &S, environment: &Environment, stable_topoheight: TopoHeight, topoheight: TopoHeight, block_version: BlockVersion) -> Vec<(Arc<Hash>, SortedTx)> {
        trace!("Cleaning up mempool...");

        // All deleted sorted txs with their hashes
        let mut deleted_transactions: Vec<(Arc<Hash>, SortedTx)> = Vec::new();

        let mut caches = HashMap::new();
        // Swap the nonces_cache with cache, so we iterate over cache and reinject it in nonces_cache
        std::mem::swap(&mut caches, &mut self.caches);

        for (key, mut cache) in caches {
            trace!("Cleaning up mempool for owner {}", key.as_address(self.mainnet));
            let nonce = match storage.get_last_nonce(&key).await {
                Ok((_, version)) => version.get_nonce(),
                Err(e) => {
                    // We get an error while retrieving the last nonce for this key,
                    // that means the key is not in storage anymore, so we can delete safely
                    // we just have to skip this iteration so it's not getting re-injected
                    warn!("Error while getting nonce for owner {}, he maybe has no nonce anymore, skipping: {}", key.as_address(self.mainnet), e);

                    // Delete all txs from this cache
                    for tx in cache.txs {
                        if let Some(sorted_tx) = self.txs.remove(&tx) {
                            deleted_transactions.push((tx, sorted_tx));
                        } else {
                            warn!("TX {} not found in mempool while deleting due to nonce error", tx);
                        }
                    }

                    continue;
                }
            };
            debug!("Owner {} has nonce {}, cache min: {}, max: {}", key.as_address(self.mainnet), nonce, cache.get_min(), cache.get_max());

            let mut delete_cache = false;
            // Check if the minimum nonce is higher than the new nonce, that means
            // all TXs will be orphaned as its suite got broken
            // or, check and delete txs if the nonce is lower than the new nonce
            // otherwise the cache is still up to date
            if cache.get_min() > nonce {
                debug!("All TXs for key {} are orphaned, deleting them because cache min is {} and last nonce is {}", key.as_address(self.mainnet), cache.get_min(), nonce);

                // Don't let ghost TXs in mempool
                for tx in cache.txs.drain(..) {
                    if let Some(sorted_tx) = self.txs.remove(&tx) {
                        debug!("Deleting ghost TX {} with {} and nonce {}", tx, sorted_tx.get_tx().get_reference(), sorted_tx.get_tx().get_nonce());
                        deleted_transactions.push((tx, sorted_tx));
                    } else {
                        warn!("Ghost TX {} not found in mempool (orphaned due to nonce)", tx);
                    }
                }

                delete_cache = true;
            } else if cache.get_min() <= nonce {
                debug!("Verifying TXs for owner {} with nonce <= {}", key.as_address(self.mainnet), nonce);
                // txs hashes to delete
                let mut hashes: HashSet<Arc<Hash>> = HashSet::with_capacity(cache.txs.len());

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
                                if v > tx_nonce {
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
                        hashes.insert(Arc::clone(hash));
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
                if !delete_cache {
                    let mut txs = Vec::with_capacity(cache.txs.len());
                    for tx_hash in &cache.txs {
                        if let Some(sorted_tx) = self.txs.get(tx_hash) {
                            txs.push((sorted_tx.get_tx(), tx_hash));
                        } else {
                            // Shouldn't happen
                            warn!("TX {} not found in mempool while verifying, deleting whole cache", tx_hash);
                            delete_cache = true;
                            break;
                        }
                    }

                    // If we have deleted a TX from this cache, we need to verify the rest of them
                    // If we don't have to delete the cache, and we didn't have any nonce collision
                    // We don't have to reverify each TXs. They must be valid
                    if !delete_cache && !hashes.is_empty() {
                        // Instead of verifiying each TX one by one, we verify them all at once
                        // This is much faster and is basically the same because:
                        // If one TX is invalid, all next TXs are invalid
                        // NOTE: this can be revert easily in case we are deleting valid TXs also,
                        // But will be slower during high traffic
                        debug!("Verifying TXs ({}) for sender {} at topoheight {}", txs.iter().map(|(_, hash)| hash.to_string()).collect::<Vec<String>>().join(", "), key.as_address(self.mainnet), topoheight);
                        let mut state = MempoolState::new(&self, storage, environment, stable_topoheight, topoheight, block_version, self.mainnet);
                        if let Err(e) = Transaction::verify_batch(txs.as_slice(), &mut state).await {
                            warn!("Error while verifying TXs for sender {}: {}", key.as_address(self.mainnet), e);
                            for (tx, hash) in txs {
                                warn!("- Deleting TX {} with {} and nonce {}", hash, tx.get_reference(), tx.get_nonce());
                                debug!("TX hex: {}", tx.to_hex());
                            }

                            // We may have only one TX invalid, but because they are all linked to each others we delete the whole cache
                            delete_cache = true;
                        } else {
                            // Update balances cache
                            if let Some((balances, multisig)) = state.get_sender_cache(&key) {
                                cache.set_balances(balances.into_iter().map(|(asset, ciphertext)| (asset.clone(), ciphertext)).collect());
                                cache.set_multisig(multisig);
                            }
                        }
                    }
                }

                if delete_cache {
                    // We empty the cache, so we can delete all txs
                    let mut local_cache = IndexSet::new();
                    mem::swap(&mut local_cache, &mut cache.txs);

                    hashes.extend(local_cache);
                }

                // now delete all necessary txs
                for hash in hashes {
                    debug!("Deleting TX {} for owner {}", hash, key.as_address(self.mainnet));
                    if let Some(sorted_tx) = self.txs.remove(&hash) {
                        deleted_transactions.push((hash, sorted_tx));
                    } else {
                        // This should never happen, but better to put a warning here
                        // in case of a lurking bug
                        warn!("TX {} not found in mempool while deleting", hash);
                    }
                }
            }

            if !delete_cache {
                debug!("Re-injecting nonce cache for owner {}", key.as_address(self.mainnet));
                self.caches.insert(key, cache);
            }
        }

        deleted_transactions
    }

    pub async fn stop(&mut self) {
        info!("Stopping mempool...");
        self.clear();
    }
}

impl SortedTx {
    // Get the inner TX
    pub fn get_tx(&self) -> &Arc<Transaction> {
        &self.tx
    }

    // Get the fee for this TX
    pub fn get_fee(&self) -> u64 {
        self.tx.get_fee()
    }

    // Get the fee rate per kB for this TX
    pub fn get_fee_rate_per_kb(&self) -> u64 {
        self.get_fee() / (self.size as u64 / BYTES_PER_KB as u64)
    }

    // Get the stored size of this TX
    pub fn get_size(&self) -> usize {
        self.size
    }

    // Get the timestamp when this TX was added to mempool
    pub fn get_first_seen(&self) -> TimestampSeconds {
        self.first_seen
    }

    // Consume the TX and return it
    pub fn consume(self) -> Arc<Transaction> {
        self.tx
    }
}

impl AccountCache {
    // Get the lowest nonce for this cache
    pub fn get_min(&self) -> Nonce {
        self.min
    }

    // Get the highest nonce for this cache
    pub fn get_max(&self) -> Nonce {
        self.max
    }

    // Get the next nonce for this cache
    // This is necessary when we have several TXs
    pub fn get_next_nonce(&self) -> Nonce {
        self.max + 1
    }

    // Get all txs hashes for this cache
    pub fn get_txs(&self) -> &IndexSet<Arc<Hash>> {
        &self.txs
    }

    // Update balances cache
    fn set_balances(&mut self, balances: HashMap<Hash, Ciphertext>) {
        self.balances = balances;
    }

    // Returns the expected balances cache after the execution of all TXs
    pub fn get_balances(&self) -> &HashMap<Hash, Ciphertext> {
        &self.balances
    }

    // Set the multisig payload
    pub fn set_multisig(&mut self, multisig: Option<MultiSigPayload>) {
        self.multisig = multisig;
    }

    // Returns the expected multisig cache after the execution of all TXs
    pub fn get_multisig(&self) -> &Option<MultiSigPayload> {
        &self.multisig
    }

    // Update the cache with a new TX
    fn update(&mut self, nonce: u64, hash: Arc<Hash>) {
        self.update_nonce_range(nonce);
        self.txs.insert(hash);
    }

    // Update the nonce range for this cache
    fn update_nonce_range(&mut self, nonce: Nonce) {
        debug_assert!(self.min <= self.max);

        if nonce < self.min {
            self.min = nonce;
        }

        if nonce > self.max {
            self.max = nonce;
        }
    }

    // Verify if a TX is in cache using its nonce
    pub fn has_tx_with_same_nonce(&self, nonce: Nonce) -> Option<&Arc<Hash>> {
        if nonce < self.min || nonce > self.max || self.txs.is_empty() {
            return None;
        }

        trace!("has tx with same nonce: {}, max: {}, min: {}, size: {}", nonce, self.max, self.min, self.txs.len());
        let index = ((nonce - self.min) % (self.max + 1 - self.min)) as usize;
        self.txs.get_index(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimated_fee_rates() {
        // Let say we have the following TXs:
        // 0.0001 XEL per KB, 0.0002 XEL per KB, 0.0003 XEL per KB, 0.0004 XEL per KB, 0.0005 XEL per KB
        let fee_rates = vec![10000, 20000, 30000, 40000, 50000];
        let estimated = super::Mempool::internal_estimate_fee_rates(fee_rates);
        assert_eq!(estimated.high, 50000);
        assert_eq!(estimated.medium, 35000);
        assert_eq!(estimated.low, 15000);
        assert_eq!(estimated.default, FEE_PER_KB);
    }

    #[test]
    fn test_estimated_fee_rates_no_tx() {
        let estimated = super::Mempool::internal_estimate_fee_rates(Vec::new());
        assert_eq!(estimated.high, FEE_PER_KB);
        assert_eq!(estimated.medium, FEE_PER_KB);
        assert_eq!(estimated.low, FEE_PER_KB);
        assert_eq!(estimated.default, FEE_PER_KB);
    }

    #[test]
    fn test_estimated_fee_rates_expensive_tx() {
        let fee_rates = vec![FEE_PER_KB * 1000];
        let estimated = super::Mempool::internal_estimate_fee_rates(fee_rates);
        assert_eq!(estimated.high, FEE_PER_KB);
        assert_eq!(estimated.medium, FEE_PER_KB);
        assert_eq!(estimated.low, FEE_PER_KB);
        assert_eq!(estimated.default, FEE_PER_KB);

        let fee_rates = vec![FEE_PER_KB * 2, FEE_PER_KB * 2, FEE_PER_KB * 3, FEE_PER_KB * 2, FEE_PER_KB * 1000];
        let estimated = super::Mempool::internal_estimate_fee_rates(fee_rates);
        assert_eq!(estimated.high, FEE_PER_KB * 1000);
        assert_eq!(estimated.medium, (FEE_PER_KB as f64 * 2.5) as u64);
        assert_eq!(estimated.low, FEE_PER_KB * 2);
        assert_eq!(estimated.default, FEE_PER_KB);
    }
}