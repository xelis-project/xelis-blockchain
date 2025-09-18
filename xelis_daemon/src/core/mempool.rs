use super::{
    error::BlockchainError,
    state::MempoolState,
    storage::Storage,
    TxCache,
    blockchain::estimate_tx_fee_per_kb,
};
use std::{
    collections::HashMap,
    sync::Arc,
    mem,
};
use linked_hash_map::LinkedHashMap;
use serde::{Serialize, Deserialize};
use indexmap::IndexSet;
use log::{debug, info, trace, warn};
use xelis_common::{
    account::Nonce,
    api::daemon::FeeRatesEstimated,
    block::{BlockVersion, TopoHeight},
    config::FEE_PER_KB,
    contract::ModuleMetadata,
    crypto::{
        elgamal::Ciphertext,
        Hash,
        PublicKey
    },
    network::Network,
    serializer::Serializer,
    time::{get_current_time_in_seconds, TimestampSeconds},
    transaction::{
        MultiSigPayload,
        Transaction
    }
};
use xelis_vm::Environment;

// Wrap a TX with its hash and size in bytes for faster access
// size of tx can be heavy to compute, so we store it here
#[derive(serde::Serialize)]
pub struct SortedTx {
    tx: Arc<Transaction>,
    // timestamp when the tx was added
    first_seen: TimestampSeconds,
    size: usize,
    fee_per_kb: u64,
    fee_limit_per_kb: u64,
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
    // LinkedHashMap is required to keep the correct insertion
    // order to easily propagate TXs in p2p
    // Older are first to be propagated, and follow nonce order
    txs: LinkedHashMap<Arc<Hash>, SortedTx>,
    // store all sender's nonce for faster finding
    caches: HashMap<PublicKey, AccountCache>,
    disable_zkp_cache: bool,
}

impl Mempool {
    // Create a new empty mempool
    pub fn new(network: Network, disable_zkp_cache: bool) -> Self {
        Mempool {
            mainnet: network.is_mainnet(),
            txs: LinkedHashMap::new(),
            caches: HashMap::new(),
            disable_zkp_cache,
        }
    }

    fn internal_estimate_fee_rates(mut fee_rates: Vec<u64>, base_fee: u64) -> FeeRatesEstimated {
        let len = fee_rates.len();
        // Top 30%
        let high_priority_count = len * 30 / 100;
        // Next 40%
        let normal_priority_count = len * 40 / 100;

        if len == 0 || high_priority_count == 0 || normal_priority_count == 0 {
            return FeeRatesEstimated {
                high: base_fee,
                medium: base_fee,
                low: base_fee,
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
            high: high.max(base_fee),
            medium: medium.max(base_fee),
            low: low.max(base_fee),
            default: FEE_PER_KB
        }
    }

    // Find the fee per kB rate estimation for the priority levels
    // For this, we need to get the median fee rate for each priority level
    pub fn estimate_fee_rates(&self, base_fee: u64) -> Result<FeeRatesEstimated, BlockchainError> { 
        let fee_rates: Vec<_> = self.txs.values()
            .map(SortedTx::get_fee_per_kb)
            .collect();

        Ok(Self::internal_estimate_fee_rates(fee_rates, base_fee))
    }

    // All checks are made in Blockchain before calling this function
    pub async fn add_tx<S: Storage>(&mut self, storage: &S, environment: &Environment<ModuleMetadata>, stable_topoheight: TopoHeight, topoheight: TopoHeight, tx_base_fee: u64, hash: Arc<Hash>, tx: Arc<Transaction>, size: usize, block_version: BlockVersion) -> Result<(), BlockchainError> {
        let mut state = MempoolState::new(&self, storage, environment, stable_topoheight, topoheight, block_version, self.mainnet, tx_base_fee);
        let tx_cache = TxCache::new(storage, self, self.disable_zkp_cache);
        tx.verify(&hash, &mut state, &tx_cache).await?;

        let (balances, multisig) = state.get_sender_cache(tx.get_source())
            .ok_or_else(|| BlockchainError::AccountNotFound(tx.get_source().as_address(self.mainnet)))?;

        let balances = balances.into_iter()
            .map(|(asset, ciphertext)| (asset.clone(), ciphertext))
            .collect();

        let nonce = tx.get_nonce();
        // update the cache for this owner
        if let Some(cache) = self.caches.get_mut(tx.get_source()) {
            // delete the TX if its in the range of already tracked nonces
            debug!("Cache found for owner {} with nonce range {}-{}, nonce = {}", tx.get_source().as_address(self.mainnet), cache.get_min(), cache.get_max(), nonce);
            cache.update(nonce, hash.clone());

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

        let (fee_per_kb, fee_limit_per_kb) = estimate_tx_fee_per_kb(storage, stable_topoheight, &tx, size, block_version).await?;
        debug!("fee per kb {} for TX {}", fee_per_kb, hash);

        let sorted_tx = SortedTx {
            size,
            first_seen: get_current_time_in_seconds(),
            fee_per_kb,
            fee_limit_per_kb,
            tx,
        };

        // insert in map
        self.txs.insert(hash, sorted_tx);

        Ok(())
    }

    // Remove a TX using its hash from mempool
    // This will recalculate the cache bounds
    pub fn remove_tx(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        let tx = self.txs.remove(hash)
            .ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
        // remove the tx hash from sorted txs
        let key = tx.get_tx()
            .get_source();

        // Should we remove the whole cache?
        // True if no other TXs available for account
        let mut delete = false;
        if let Some(cache) = self.caches.get_mut(key) {
            // Shift remove is O(n) on average, but we need to preserve the order
            if !cache.txs.shift_remove(hash) {
                warn!("TX {} not found in mempool while deleting", hash);
            }

            trace!("TX {} removed from cache", hash);
            if !delete {
                trace!("Updating cache bounds");
                let mut max: Option<u64> = None;
                let mut min: Option<u64> = None;
                // Update cache bounds
                for tx_hash in cache.txs.iter() {
                    let tx = self.txs.get(tx_hash)
                        .ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;

                    let tx_nonce = tx.get_tx().get_nonce();

                    // Update cache highest bounds
                    if max.is_none_or(|v| v < tx_nonce) {
                        max = Some(tx_nonce);
                    }

                    if min.is_none_or(|v| v > tx_nonce) {
                        min = Some(tx_nonce);
                    }
                }

                if let (Some(min), Some(max)) = (min, max) {
                    trace!("Updating cache bounds to {}-{}", min, max);
                    cache.min = min;
                    cache.max = max;
                } else {
                    delete = true;
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
        self.txs.get(hash)
            .ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))
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
    pub fn get_txs(&self) -> &LinkedHashMap<Arc<Hash>, SortedTx> {
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

    pub async fn try_add_back_txs<S: Storage>(
        &mut self,
        storage: &S,
        transactions: impl Iterator<Item = Hash>,
        environment: &Environment<ModuleMetadata>,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        block_version: BlockVersion,
        tx_base_fee: u64,
    ) -> Result<Vec<(Arc<Hash>, Arc<Transaction>)>, BlockchainError> {
        trace!("try add back txs");

        // Group the TXs per source
        let mut grouped = HashMap::new();
        for hash in transactions {
            let tx = storage.get_transaction(&hash).await?
                .into_arc();

            grouped.entry(tx.get_source().clone())
                .or_insert_with(Vec::new)
                .push((Arc::new(hash), tx.size(), tx));
        }

        let mut orphaned = Vec::new();
        for (source, mut txs) in grouped {
            let cache = self.caches.remove(&source);

            // append TXs that were previously in the cache
            if let Some(cache) = cache {
                for hash in cache.txs.into_iter() {
                    let tx = self.txs.remove(&hash)
                        .ok_or_else(|| BlockchainError::TxNotFound(hash.as_ref().clone()))?;

                    txs.push((hash, tx.size, tx.tx));
                }
            }

            // Process TXs normally
            // TODO: maybe we can batch it for faster results
            // We can also mark them as verified in ZKP Cache to only check
            // dynamic
            for (hash, size, transaction) in txs {
                if self.contains_tx(&hash) {
                    continue;
                }

                if let Err(e) = self.add_tx(storage, environment, stable_topoheight, topoheight, tx_base_fee, hash.clone(), transaction.clone(), size, block_version).await {
                    warn!("Error while adding back TX {} for {}: {}", hash, source.as_address(self.mainnet), e);
                    orphaned.push((hash, transaction));
                }
            }
        }

        Ok(orphaned)
    }

    // delete all old txs not compatible anymore with current state of chain
    // this is called when a new block is added to the chain
    // Because of DAG reorg, we can't only check updated keys from new block,
    // as a block could be orphaned and the nonce order would change
    // So we need to check all keys from mempool and compare it from storage
    // This is cleaning all TXs with the minimal TX fee per KB
    // instead of the actual required base fee to not invalid them and simply
    // deplay them until its free again
    pub async fn clean_up<S: Storage>(
        &mut self,
        storage: &S,
        environment: &Environment<ModuleMetadata>,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        block_version: BlockVersion,
        tx_base_fee: u64,
    ) -> Result<Vec<(Arc<Hash>, SortedTx)>, BlockchainError> {
        trace!("Cleaning up mempool...");

        // All deleted sorted txs with their hashes
        let mut deleted_transactions: Vec<(Arc<Hash>, SortedTx)> = Vec::new();

        let mut caches = HashMap::new();
        // Swap the nonces_cache with cache, so we iterate over cache and reinject it in nonces_cache
        std::mem::swap(&mut caches, &mut self.caches);

        for (key, mut cache) in caches {
            debug!("cleaning up mempool for source {} at topoheight {}", key.as_address(self.mainnet), topoheight);
            let nonce = match storage.get_nonce_at_maximum_topoheight(&key, topoheight).await? {
                Some((_, version)) => version.get_nonce(),
                None => {
                    // We get an error while retrieving the last nonce for this key,
                    // that means the key is not in storage anymore, so we can delete safely
                    // we just have to skip this iteration so it's not getting re-injected
                    warn!("No nonce found for source {} at topoheight {}, deleting whole cache (commit point: {})", key.as_address(self.mainnet), topoheight, storage.has_commit_point().await?);

                    // Delete all txs from this cache
                    for tx in cache.txs {
                        let sorted_tx = self.txs.remove(&tx)
                            .ok_or_else(|| BlockchainError::TxNotFound(tx.as_ref().clone()))?;

                        deleted_transactions.push((tx, sorted_tx));
                    }

                    continue;
                }
            };
            debug!("source {} has nonce {} and cache [{}-{}]", key.as_address(self.mainnet), nonce, cache.get_min(), cache.get_max());

            let mut delete_cache = false;
            // Check if the account nonce is below cache lowest nonce, that means
            // all TXs will be orphaned as its suite got broken
            // or, check and delete txs if the nonce is lower than the new nonce
            // otherwise the cache is still up to date
            if nonce < cache.get_min() {
                warn!("All TXs for {} are orphaned, deleting them because cache min is {} and last nonce is {}", key.as_address(self.mainnet), cache.get_min(), nonce);

                // Don't let ghost TXs in mempool
                for tx in cache.txs.drain(..) {
                    let sorted_tx = self.txs.remove(&tx)
                        .ok_or_else(|| BlockchainError::TxNotFound(tx.as_ref().clone()))?;

                    deleted_transactions.push((tx, sorted_tx));
                }

                delete_cache = true;
            } else if nonce > cache.get_min() {
                // Account nonce is above our min, which means some TXs are processed
                // We must check the next ones
                debug!("Verifying TXs for owner {} with nonce < {}", key.as_address(self.mainnet), nonce);
                // txs hashes to delete
                let mut deleted_txs_hashes = IndexSet::with_capacity(cache.txs.len());

                // filter all txs hashes which are not found
                // or where its nonce is smaller than the new nonce
                // TODO when drain_filter is stable, use it (allow to get all hashes deleted)
                let mut max: Option<u64> = None;
                let mut min: Option<u64> = None;

                cache.txs.retain(|hash| {
                    // Delete by default
                    let mut delete = true;

                    if let Some(tx) = self.txs.get(hash) {
                        let tx_nonce = tx.get_tx().get_nonce();
                        // If TX is still compatible with new nonce, update bounds
                        if tx_nonce >= nonce {
                            // Update cache highest bounds
                            if max.is_none_or(|v| v < tx_nonce) {
                                max = Some(tx_nonce);
                            }

                            if min.is_none_or(|v| v > tx_nonce) {
                                min = Some(tx_nonce);
                            }
                            delete = false;
                        }
                    }

                    // Add hash in list if we delete it
                    if delete {
                        deleted_txs_hashes.insert(Arc::clone(hash));
                    }
                    !delete
                });

                // Update cache bounds
                if let (Some(min), Some(max)) = (min, max) {
                    debug!("Update cache bounds: [{}-{}]", min, max);
                    cache.min = min;
                    cache.max = max;
                } else {
                    debug!("no min/max found, deleting cache");
                    delete_cache = true;
                }

                // Cache is not empty yet, but we deleted some TXs from it, balances may be out-dated, verify TXs left
                // We must have deleted a TX from its list to trigger a new re-check
                if !delete_cache && !deleted_txs_hashes.is_empty() {
                    // Instead of checking ALL the TXs
                    // We can do the following optimization:
                    // As we know that each TXs added in mempool are validated
                    // and compatible with previous, we can simply check the next (first) TX
                    // to ensure its still valid without verifying all the others TXs
                    // as we already ensured that the order and ZKPs are valid.

                    // If we have deleted a TX from this cache, we need to verify the rest of them
                    // If we don't have to delete the cache, and we didn't have any nonce collision
                    // We don't have to reverify each TXs. They must be valid
                    let first_tx =  cache.txs.first()
                        .and_then(|hash| self.txs.get(hash)
                            .map(|tx| (tx, hash))
                        );

                    let tx_cache = TxCache::new(storage, &self, self.disable_zkp_cache);
                    if let Some((next_tx, tx_hash)) = first_tx {
                        let mut state = MempoolState::new(&self, storage, environment, stable_topoheight, topoheight, block_version, self.mainnet, tx_base_fee);
                        if let Err(e) = Transaction::verify(next_tx.get_tx(), &tx_hash, &mut state, &tx_cache).await {
                            warn!("Error while verifying TXs for source {}: {}", key.as_address(self.mainnet), e);

                            // We may have only one TX invalid, but because they are all linked to each others we delete the whole cache
                            delete_cache = true;
                        }
                    } else {
                        debug!("no next TX for {}, deleting cache", key.as_address(self.mainnet));
                        delete_cache = true;
                    }
                }

                if delete_cache {
                    // We empty the cache, so we can delete all txs
                    let mut local_cache = IndexSet::new();
                    mem::swap(&mut local_cache, &mut cache.txs);

                    deleted_txs_hashes.extend(local_cache);
                }

                // now delete all necessary txs
                for tx in deleted_txs_hashes {
                    let sorted_tx = self.txs.remove(&tx)
                        .ok_or_else(|| BlockchainError::TxNotFound(tx.as_ref().clone()))?;
                    debug!("Deleted TX {} for source {} with nonce {}, txs left: {}", tx, key.as_address(self.mainnet), sorted_tx.get_tx().get_nonce(), cache.txs.len());

                    deleted_transactions.push((tx, sorted_tx));
                }

                // Delete the cache if its empty
                delete_cache |= cache.txs.is_empty();
            } else {
                debug!("{} hasn't changed, skipping it", key.as_address(self.mainnet));
            }

            if !delete_cache {
                debug!("Re-injecting nonce cache for owner {}", key.as_address(self.mainnet));
                self.caches.insert(key, cache);
            }
        }

        Ok(deleted_transactions)
    }

    pub async fn stop(&mut self) {
        info!("Stopping mempool...");
        self.clear();
    }
}

impl SortedTx {
    // Get the inner TX
    #[inline(always)]
    pub fn get_tx(&self) -> &Arc<Transaction> {
        &self.tx
    }

    // Get the fee for this TX
    #[inline(always)]
    pub fn get_fee(&self) -> u64 {
        self.tx.get_fee()
    }

    // Get the fee rate per kB for this TX
    #[inline(always)]
    pub fn get_fee_per_kb(&self) -> u64 {
        self.fee_per_kb
    }

    // Get the fee limit per kB for this TX
    #[inline(always)]
    pub fn get_fee_limit_per_kb(&self) -> u64 {
        self.fee_limit_per_kb
    }

    // Get the stored size of this TX
    #[inline(always)]
    pub fn get_size(&self) -> usize {
        self.size
    }

    // Get the timestamp when this TX was added to mempool
    #[inline(always)]
    pub fn get_first_seen(&self) -> TimestampSeconds {
        self.first_seen
    }

    // Consume the TX and return it
    #[inline(always)]
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
        let estimated = super::Mempool::internal_estimate_fee_rates(fee_rates, FEE_PER_KB);
        assert_eq!(estimated.high, 50000);
        assert_eq!(estimated.medium, 35000);
        assert_eq!(estimated.low, 15000);
        assert_eq!(estimated.default, FEE_PER_KB);
    }

    #[test]
    fn test_estimated_fee_rates_no_tx() {
        let estimated = super::Mempool::internal_estimate_fee_rates(Vec::new(), FEE_PER_KB);
        assert_eq!(estimated.high, FEE_PER_KB);
        assert_eq!(estimated.medium, FEE_PER_KB);
        assert_eq!(estimated.low, FEE_PER_KB);
        assert_eq!(estimated.default, FEE_PER_KB);
    }

    #[test]
    fn test_estimated_fee_rates_expensive_tx() {
        let fee_rates = vec![FEE_PER_KB * 1000];
        let estimated = super::Mempool::internal_estimate_fee_rates(fee_rates, FEE_PER_KB);
        assert_eq!(estimated.high, FEE_PER_KB);
        assert_eq!(estimated.medium, FEE_PER_KB);
        assert_eq!(estimated.low, FEE_PER_KB);
        assert_eq!(estimated.default, FEE_PER_KB);

        let fee_rates = vec![FEE_PER_KB * 2, FEE_PER_KB * 2, FEE_PER_KB * 3, FEE_PER_KB * 2, FEE_PER_KB * 1000];
        let estimated = super::Mempool::internal_estimate_fee_rates(fee_rates, FEE_PER_KB);
        assert_eq!(estimated.high, FEE_PER_KB * 1000);
        assert_eq!(estimated.medium, (FEE_PER_KB as f64 * 2.5) as u64);
        assert_eq!(estimated.low, FEE_PER_KB * 2);
        assert_eq!(estimated.default, FEE_PER_KB);
    }
}