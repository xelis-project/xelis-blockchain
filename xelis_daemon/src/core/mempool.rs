use super::{
    error::BlockchainError,
    state::{ChainState, MempoolProvider},
    storage::Storage,
    TxCache,
    blockchain::{ContractEnvironments, estimate_tx_fee_per_kb},
};
use std::{
    collections::{BTreeSet, HashMap},
    cmp::Ordering,
    sync::Arc,
    mem,
};
use linked_hash_table::{LinkedHashMap, LinkedHashSet};
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};
use indexmap::IndexSet;
use log::{debug, info, trace, warn};
use xelis_common::{
    account::Nonce,
    api::daemon::FeeRatesEstimated,
    block::{BlockVersion, TopoHeight},
    config::FEE_PER_KB,
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
        Transaction,
        verify::TrustedZKPCache
    }
};

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
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccountCache {
    // lowest nonce used
    min: Nonce,
    // highest nonce used
    max: Nonce,
    // all txs for this user ordered by nonce
    #[schemars(with = "Vec<Arc<Hash>>")]
    txs: LinkedHashSet<Arc<Hash>>,
    // Expected balances after all txs in this cache
    // This is also used to verify the validity of the TX spendings
    balances: HashMap<Hash, Ciphertext>,
    // Expected multisig after all txs in this cache
    multisig: Option<MultiSigPayload>
}

// Entry in the fee index: sorted ascending by (fee_per_kb, hash) so that
// the front of the BTreeSet is always the cheapest TX in the mempool.
struct TxFeeEntry {
    fee_per_kb: u64,
    hash: Arc<Hash>,
}

impl PartialEq for TxFeeEntry {
    fn eq(&self, other: &Self) -> bool {
        self.fee_per_kb == other.fee_per_kb && self.hash == other.hash
    }
}

impl Eq for TxFeeEntry {}

impl PartialOrd for TxFeeEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxFeeEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.fee_per_kb.cmp(&other.fee_per_kb)
            .then_with(|| self.hash.cmp(&other.hash))
    }
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
    // Whether to disable ZKP cache when verifying TXs in mempool
    disable_zkp_cache: bool,
    // Maximum time in seconds a TX can stay in the mempool (0 = no expiration)
    tx_expiration_time: u64,
    // Maximum total memory usage in bytes before evicting low-fee TXs
    max_memory_usage: u64,
    // Running total of all TX sizes in bytes
    memory_usage: usize,
    // Fee-ordered index for O(log n) eviction: front is the cheapest TX
    ordered_by_fee: BTreeSet<TxFeeEntry>,
}

impl Mempool {
    // Create a new empty mempool
    pub fn new(network: Network, disable_zkp_cache: bool, tx_expiration_time: u64, max_memory_usage: u64) -> Self {
        Mempool {
            mainnet: network.is_mainnet(),
            txs: LinkedHashMap::new(),
            caches: HashMap::new(),
            disable_zkp_cache,
            tx_expiration_time,
            max_memory_usage,
            memory_usage: 0,
            ordered_by_fee: BTreeSet::new(),
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

    /// Add a TX to mempool after verifying it
    // All checks MUST be made AND are made in Blockchain before calling this function
    #[inline]
    pub async fn add_tx<S: Storage>(
        &mut self,
        storage: &S,
        environments: &ContractEnvironments,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        tx_base_fee: u64,
        base_height: u64,
        hash: Arc<Hash>,
        tx: Arc<Transaction>,
        size: usize,
        block_version: BlockVersion,
    ) -> Result<(), BlockchainError> {
        debug!("Adding TX {} to mempool", hash);

        let provider = MempoolProvider {
            mempool: self,
            storage
        };
        let mut state = ChainState::new(&provider, environments, stable_topoheight, topoheight, topoheight, block_version, tx_base_fee, base_height);
        let tx_cache = TxCache::new(storage, self, self.disable_zkp_cache);
        tx.verify(&hash, &mut state, &tx_cache).await?;

        let (balances, multisig) = state.get_sender_cache(tx.get_source())
            .ok_or_else(|| BlockchainError::AccountNotFound(tx.get_source().as_address(self.mainnet)))?;

        self.add_tx_internal(storage, stable_topoheight, hash, tx, size, block_version, balances, multisig).await
    }

    /// Add a TX to mempool without verifying the static proofs part of it
    pub async fn add_known_tx<S: Storage>(
        &mut self,
        storage: &S,
        environments: &ContractEnvironments,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        tx_base_fee: u64,
        base_height: u64,
        hash: Arc<Hash>,
        tx: Arc<Transaction>,
        size: usize,
        block_version: BlockVersion,
    ) -> Result<(), BlockchainError> {
        debug!("Adding trusted TX {} to mempool", hash);

        let provider = MempoolProvider {
            mempool: self,
            storage
        };
        let mut state = ChainState::new(&provider, environments, stable_topoheight, topoheight, topoheight, block_version, tx_base_fee, base_height);
        tx.verify(&hash, &mut state, &TrustedZKPCache).await?;

        let (balances, multisig) = state.get_sender_cache(tx.get_source())
            .ok_or_else(|| BlockchainError::AccountNotFound(tx.get_source().as_address(self.mainnet)))?;

        self.add_tx_internal(storage, stable_topoheight, hash, tx, size, block_version, balances, multisig).await
    }

    /// Add a TX to mempool without verifying it
    async fn add_tx_internal<S: Storage>(
        &mut self,
        storage: &S,
        stable_topoheight: TopoHeight,
        hash: Arc<Hash>,
        tx: Arc<Transaction>,
        size: usize,
        block_version: BlockVersion,
        balances: HashMap<Hash, Ciphertext>,
        multisig: Option<MultiSigPayload>
    ) -> Result<(), BlockchainError> {
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
            let mut txs = LinkedHashSet::new();
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
        self.txs.insert(hash.clone(), sorted_tx);
        self.memory_usage += size;
        self.ordered_by_fee.insert(TxFeeEntry { fee_per_kb, hash: hash.clone() });

        let evicted = self.evict_for_memory_limit()?;

        // TX Hash got evicted because of memory limit, we need to remove it from mempool and return an error
        if !evicted.is_empty() && !self.txs.contains_key(&hash) {
            return Err(BlockchainError::MempoolMemoryLimit)
        }

        Ok(())
    }

    // Evict accounts containing the lowest-fee TXs until total memory usage is within
    // the configured limit. TXs of the same account are chained, so deleting one
    // without recomputing cache state would invalidate the rest.
    fn evict_for_memory_limit(&mut self) -> Result<Vec<(Arc<Hash>, SortedTx)>, BlockchainError> {
        let mut evicted = Vec::new();
        while self.memory_usage as u64 > self.max_memory_usage {
            // O(log n): the BTreeSet front is always the cheapest TX in the mempool
            let lowest_hash = match self.ordered_by_fee.first() {
                Some(e) => Arc::clone(&e.hash),
                None => break,
            };

            // Find the account that owns this TX
            let source = match self.txs.get(&lowest_hash) {
                Some(tx) => tx.get_tx().get_source().clone(),
                None => {
                    warn!("TX {} not found in mempool while evicting for memory limit, skipping", lowest_hash);
                    // Shouldn't happen; clean up the orphaned index entry and continue
                    self.ordered_by_fee.pop_first();
                    continue;
                }
            };

            let mut deleted_txs_hashes = IndexSet::new();
            if let Some(cache) = self.caches.remove(&source) {
                deleted_txs_hashes.extend(cache.txs);
            } else {
                warn!("No cache found for owner {} while evicting TX {}", source.as_address(self.mainnet), lowest_hash);
                deleted_txs_hashes.insert(lowest_hash);
            }

            if deleted_txs_hashes.is_empty() {
                warn!("No TX selected while evicting for memory limit, stopping eviction");
                break;
            }

            for hash in deleted_txs_hashes {
                if let Some(sorted_tx) = self.txs.remove(&hash) {
                    self.memory_usage = self.memory_usage.saturating_sub(sorted_tx.size);
                    self.ordered_by_fee.remove(&TxFeeEntry { fee_per_kb: sorted_tx.fee_per_kb, hash: Arc::clone(&hash) });
                    debug!("Evicted TX {} for memory limit with fee per kB {}", hash, sorted_tx.fee_per_kb);
                    evicted.push((hash, sorted_tx));
                } else {
                    warn!("TX {} not found while finalizing memory-limit eviction", hash);
                    self.ordered_by_fee.retain(|entry| entry.hash != hash);
                }
            }
        }

        Ok(evicted)
    }

    // Remove a TX using its hash from mempool
    // This will recalculate the cache bounds
    pub fn remove_tx(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        let tx = self.txs.remove(hash)
            .ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
        self.memory_usage -= tx.size;
        self.ordered_by_fee.remove(&TxFeeEntry { fee_per_kb: tx.fee_per_kb, hash: Arc::new(hash.clone()) });
        // remove the tx hash from sorted txs
        let key = tx.get_tx()
            .get_source();

        // Should we remove the whole cache?
        // True if no other TXs available for account
        let mut delete = false;
        if let Some(cache) = self.caches.get_mut(key) {
            if !cache.txs.remove(hash) {
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

    // Returns the count of txs in mempool
    pub fn size(&self) -> usize {
        self.txs.len()
    }

    // Get memory usage in bytes of mempool
    pub fn memory_usage(&self) -> usize {
        self.memory_usage
    }

    // Get the configured memory usage limit in bytes of mempool
    pub fn get_max_memory_usage(&self) -> u64 {
        self.max_memory_usage
    }

    // Clear all txs and caches in mempool
    pub fn clear(&mut self) {
        self.txs.clear();
        self.caches.clear();
        self.memory_usage = 0;
        self.ordered_by_fee.clear();
    }

    // Drain all txs from mempool
    pub fn drain(&mut self) -> Vec<(Hash, Arc<Transaction>)> {
        let mut txs = Vec::with_capacity(self.txs.len());
        for (hash, sorted_tx) in self.txs.drain() {
            txs.push((hash.as_ref().clone(), sorted_tx.consume()));
        }

        self.caches.clear();
        self.memory_usage = 0;
        self.ordered_by_fee.clear();

        txs
    }

    pub async fn try_add_back_txs<S: Storage>(
        &mut self,
        storage: &S,
        transactions: impl Iterator<Item = Hash>,
        environments: &ContractEnvironments,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        block_version: BlockVersion,
        tx_base_fee: u64,
        base_height: u64,
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
                    self.memory_usage -= tx.size;
                    self.ordered_by_fee.remove(&TxFeeEntry { fee_per_kb: tx.fee_per_kb, hash: Arc::clone(&hash) });
                    txs.push((hash, tx.size, tx.tx));
                }
            }

            for (hash, size, transaction) in txs {
                if self.contains_tx(&hash) {
                    continue;
                }

                if let Err(e) = self.add_known_tx(storage, environments, stable_topoheight, topoheight, tx_base_fee, base_height, hash.clone(), transaction.clone(), size, block_version).await {
                    debug!("Error while adding back TX in mempool {} for {}: {}", hash, source.as_address(self.mainnet), e);
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
        environments: &ContractEnvironments,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        block_version: BlockVersion,
        tx_base_fee: u64,
        base_height: u64,
        full: bool,
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
                    warn!("No nonce found for source {} at topoheight {}, deleting whole cache (commit point: {})", key.as_address(self.mainnet), topoheight, storage.has_snapshot().await?);

                    // Delete all txs from this cache
                    for tx in cache.txs {
                        let sorted_tx = self.txs.remove(&tx)
                            .ok_or_else(|| BlockchainError::TxNotFound(tx.as_ref().clone()))?;
                        self.memory_usage -= sorted_tx.size;
                        self.ordered_by_fee.remove(&TxFeeEntry { fee_per_kb: sorted_tx.fee_per_kb, hash: Arc::clone(&tx) });
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
                for tx in cache.txs.drain() {
                    let sorted_tx = self.txs.remove(&tx)
                        .ok_or_else(|| BlockchainError::TxNotFound(tx.as_ref().clone()))?;
                    self.memory_usage -= sorted_tx.size;
                    self.ordered_by_fee.remove(&TxFeeEntry { fee_per_kb: sorted_tx.fee_per_kb, hash: Arc::clone(&tx) });
                    deleted_transactions.push((tx, sorted_tx));
                }

                delete_cache = true;
            } else {
                debug!("Verifying TXs for source {}", key.as_address(self.mainnet));
                
                // Account nonce is above our min, which means some TXs are processed
                // We must check the next ones

                // txs hashes to delete
                let mut deleted_txs_hashes = IndexSet::with_capacity(cache.txs.len());
                if nonce > cache.get_min() {
                    delete_cache = cache.clean_cache(&self.txs, nonce, &mut deleted_txs_hashes);
                }

                // Cache is not empty yet, but we deleted some TXs from it, balances may be out-dated, verify TXs left
                // We must have deleted a TX from its list to trigger a new re-check
                if !delete_cache && (!deleted_txs_hashes.is_empty() || full) {
                    // Instead of checking ALL the TXs
                    // We can do the following optimization:
                    // As we know that each TXs added in mempool are validated
                    // and compatible with previous, we can simply check the next (first) TX
                    // to ensure its still valid without verifying all the others TXs
                    // as we already ensured that the order and ZKPs are valid.

                    // If we have deleted a TX from this cache, we need to verify the rest of them
                    // If we don't have to delete the cache, and we didn't have any nonce collision
                    // We don't have to reverify each TXs. They must be valid
                    let first_tx =  cache.txs.front()
                        .and_then(|hash| self.txs.get(hash)
                            .map(|tx| (tx, hash))
                        );

                    let tx_cache = TxCache::new(storage, &self, self.disable_zkp_cache);
                    if let Some((next_tx, tx_hash)) = first_tx {
                        let provider = MempoolProvider {
                            mempool: self,
                            storage
                        };
                        let mut state = ChainState::new(&provider, environments, stable_topoheight, topoheight, topoheight, block_version, tx_base_fee, base_height);
                        if let Err(e) = Transaction::verify(next_tx.get_tx(), &tx_hash, &mut state, &tx_cache).await {
                            warn!("Error while verifying TXs for source {}: {}", key.as_address(self.mainnet), e);

                            // We may have only one TX invalid, but because they are all linked to each others we delete the whole cache
                            delete_cache = true;
                        }
                    } else {
                        debug!("no next TX for {}, deleting cache", key.as_address(self.mainnet));
                        delete_cache = true;
                    }
                } else {
                    debug!("{} hasn't partially changed, delete cache: {}", key.as_address(self.mainnet), delete_cache);
                }

                if delete_cache {
                    // We empty the cache, so we can delete all txs
                    let mut local_cache = LinkedHashSet::new();
                    mem::swap(&mut local_cache, &mut cache.txs);

                    deleted_txs_hashes.extend(local_cache);
                }

                // now delete all necessary txs
                for tx in deleted_txs_hashes {
                    let sorted_tx = self.txs.remove(&tx)
                        .ok_or_else(|| BlockchainError::TxNotFound(tx.as_ref().clone()))?;

                    self.memory_usage -= sorted_tx.size;
                    self.ordered_by_fee.remove(&TxFeeEntry { fee_per_kb: sorted_tx.fee_per_kb, hash: Arc::clone(&tx) });

                    debug!("Deleted TX {} for source {} with nonce {}, txs left: {}", tx, key.as_address(self.mainnet), sorted_tx.get_tx().get_nonce(), cache.txs.len());

                    deleted_transactions.push((tx, sorted_tx));
                }

                // Delete the cache if its empty
                delete_cache |= cache.txs.is_empty();
            }

            // Check for TX expiration: if the oldest TX (lowest nonce) in this account
            // has exceeded the expiration time, evict all TXs for this account.
            // The first TX in the cache is always the oldest since TXs are added in nonce order.
            if !delete_cache && self.tx_expiration_time > 0 {
                let now = get_current_time_in_seconds();
                if let Some(first_hash) = cache.txs.front() {
                    if let Some(first_tx) = self.txs.get(first_hash) {
                        let age = now.saturating_sub(first_tx.first_seen);
                        if age >= self.tx_expiration_time {
                            debug!("evicting expired TXs for {} (oldest TX age: {}s >= expiration: {}s)", key.as_address(self.mainnet), age, self.tx_expiration_time);
                            for hash in cache.txs.drain() {
                                if let Some(sorted_tx) = self.txs.remove(&hash) {
                                    self.memory_usage -= sorted_tx.size;
                                    self.ordered_by_fee.remove(&TxFeeEntry { fee_per_kb: sorted_tx.fee_per_kb, hash: Arc::clone(&hash) });
                                    deleted_transactions.push((hash, sorted_tx));
                                }
                            }
                            delete_cache = true;
                        }
                    }
                }
            }

            if !delete_cache {
                debug!("Re-injecting nonce cache for owner {}", key.as_address(self.mainnet));
                self.caches.insert(key, cache);
            }
        }

        // Re-enforce memory limit after nonce/expiration cleanup
        deleted_transactions.extend(self.evict_for_memory_limit()?);

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
    pub fn get_txs(&self) -> &LinkedHashSet<Arc<Hash>> {
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
    pub fn has_tx_with_same_nonce(&self, nonce: Nonce) -> bool {
        if nonce < self.min || nonce > self.max || self.txs.is_empty() {
            return false;
        }

        trace!("has tx with same nonce: {}, max: {}, min: {}, size: {}", nonce, self.max, self.min, self.txs.len());
        let index = ((nonce - self.min) % (self.max + 1 - self.min)) as usize;
        index < self.txs.len()
    }

    pub fn get_index_for_nonce(&self, nonce: Nonce) -> Option<usize> {
        if nonce < self.min || nonce > self.max || self.txs.is_empty() {
            return None;
        }

        let index = ((nonce - self.min) % (self.max + 1 - self.min)) as usize;
        if index < self.txs.len() {
            Some(index)
        } else {
            None
        }
    }

    // Returns true if it should be deleted, false if it should be kept
    fn clean_cache(&mut self, txs: &LinkedHashMap<Arc<Hash>, SortedTx>, new_nonce: Nonce, deleted_txs_hashes: &mut IndexSet<Arc<Hash>>) -> bool {
        // filter all txs hashes which are not found
        // or where its nonce is smaller than the new nonce
        // TODO when drain_filter is stable, use it (allow to get all hashes deleted)
        let mut max: Option<u64> = None;
        let mut min: Option<u64> = None;

        self.txs.retain(|hash| {
            // Delete by default
            let mut delete = true;
            if let Some(tx) = txs.get(hash) {
                let tx_nonce = tx.get_tx().get_nonce();
                // If TX is still compatible with new nonce, update bounds
                if tx_nonce >= new_nonce {
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
            self.min = min;
            self.max = max;
            false
        } else {
            debug!("no min/max found, deleting cache");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, collections::HashMap, sync::Arc};
    use xelis_common::{
        account::{CiphertextCache, VersionedBalance, VersionedNonce},
        config::{COIN_VALUE, FEE_PER_KB, XELIS_ASSET},
        crypto::{Address, Hash, Hashable},
        transaction::{
            MultiSigPayload,
            Reference,
            TxVersion,
            builder::{FeeBuilder, MultiSigBuilder, TransactionBuilder, TransactionTypeBuilder},
            mock::{TrackedAccount, TrackedAccountState, create_transfer_tx_for_account, create_multisig_transfer_tx},
            verify::VerificationError,
        },
        versioned::Versioned,
        network::Network,
    };
    use crate::core::{
        blockchain::ContractEnvironments,
        error::BlockchainError,
        storage::{MemoryStorage, BalanceProvider, MultiSigProvider, NonceProvider, AccountProvider},
    };
    use super::*;

    /// Setup a TrackedAccount in a MemoryStorage: registers the account, sets its nonce to 0,
    /// and writes its XELIS encrypted balance so the chain-state verifier can find it.
    async fn setup_account(storage: &mut MemoryStorage, account: &TrackedAccount) {
        let pk = account.get_public_key();

        let tracked_balance = account.balances.get(&XELIS_ASSET)
            .expect("account must have an XELIS balance set via set_balance()");

        let mut cache = tracked_balance.ciphertext.clone();
        let ciphertext = cache.computable()
            .expect("ciphertext must be decompressible")
            .clone();

        let versioned_balance = VersionedBalance::new(
            CiphertextCache::Decompressed(None, ciphertext),
            None,
        );

        storage.set_last_balance_to(&pk, &XELIS_ASSET, 0, &versioned_balance).await
            .expect("set_last_balance_to failed");
        storage.set_last_nonce_to(&pk, 0, &VersionedNonce::new(0, None)).await
            .expect("set_last_nonce_to failed");
        storage.set_account_registration_topoheight(&pk, 0).await
            .expect("set_account_registration_topoheight failed");
    }

    fn make_reference() -> Reference {
        Reference { topoheight: 0, hash: Hash::zero() }
    }

    #[tokio::test]
    async fn test_add_valid_tx() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let tx = create_transfer_tx_for_account(
            &mut alice,
            bob.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("failed to create transfer tx");

        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
        add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await
            .expect("add_tx should succeed for a valid TX");

        assert_eq!(mempool.size(), 1);
    }

    #[tokio::test]
    async fn test_add_multiple_txs_same_source() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 500 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        for _ in 0..3 {
            let tx = create_transfer_tx_for_account(
                &mut alice,
                bob.address(),
                COIN_VALUE,
                None,
                TxVersion::V2,
                make_reference(),
            ).expect("failed to create transfer tx");

            add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await
                .expect("add_tx should succeed for sequential TXs from same source");
        }

        assert_eq!(mempool.size(), 3);
    }

    #[tokio::test]
    async fn test_add_txs_different_sources() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let mut bob = TrackedAccount::new();
        bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &bob).await;

        let carol = TrackedAccount::new();
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let tx_a = create_transfer_tx_for_account(
            &mut alice,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("alice tx failed");
        let tx_b = create_transfer_tx_for_account(
            &mut bob,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("bob tx failed");

        for tx in [tx_a, tx_b] {
            add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await
                .expect("add_tx should succeed for different sources");
        }

        assert_eq!(mempool.size(), 2);
    }

    #[tokio::test]
    async fn test_reject_duplicate_tx() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();

        let tx = create_transfer_tx_for_account(
            &mut alice,
            bob.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("failed to create transfer tx");

        let tx = Arc::new(tx);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        // First add succeeds
        add_tx_to_mempool(&mut mempool, &storage, tx.clone()).await
            .expect("first add should succeed");

        // Second add with the same nonce should be rejected
        let err = add_tx_to_mempool(&mut mempool, &storage, tx.clone()).await
            .expect_err("duplicate nonce should be rejected");

        assert!(
            matches!(err, BlockchainError::VerificationError(VerificationError::InvalidNonce(..))),
            "expected VerificationError::InvalidNonce for duplicate nonce, got: {:?}", err
        );
    }

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

    /// Build a MultiSig setup/delete TX from `account`, optionally signed by co-signers.
    /// When `account` already has multisig configured, `signers` must carry the required co-sigs.
    fn create_multisig_setup_tx(
        account: &mut TrackedAccount,
        participants: Vec<Address>,
        threshold: u8,
        signers: &[(u8, &TrackedAccount)],
    ) -> Transaction {
        let mut state = TrackedAccountState {
            balances: account.balances.clone(),
            nonce: account.nonce,
            reference: make_reference(),
        };
        let required_thresholds = if signers.is_empty() { None } else { Some(signers.len() as u8) };
        let builder = TransactionBuilder::new(
            TxVersion::V2,
            account.keypair.get_public_key().compress(),
            required_thresholds,
            TransactionTypeBuilder::MultiSig(MultiSigBuilder {
                participants: participants.into_iter().collect(),
                threshold,
            }),
            FeeBuilder::default(),
        );
        if signers.is_empty() {
            let tx = builder.build(&mut state, &account.keypair).unwrap();
            account.balances = state.balances;
            account.nonce = state.nonce;
            tx
        } else {
            let mut unsigned = builder.build_unsigned(&mut state, &account.keypair).unwrap();
            for (id, signer) in signers {
                unsigned.sign_multisig(&signer.keypair, *id);
            }
            let tx = unsigned.finalize(&account.keypair);
            account.balances = state.balances;
            account.nonce = state.nonce;
            tx
        }
    }

    /// Insert a MultiSigPayload directly into storage for an account.
    async fn setup_multisig_in_storage(storage: &mut MemoryStorage, account: &TrackedAccount, payload: MultiSigPayload) {
        let pk = account.get_public_key();
        let versioned = Versioned::new(Some(Cow::Owned(payload)), None);
        storage.set_last_multisig_to(&pk, 0, versioned).await.unwrap();
    }

    /// Convenience wrapper: add a TX to the mempool with sensible defaults.
    async fn add_tx_to_mempool(
        mempool: &mut Mempool,
        storage: &MemoryStorage,
        tx: Arc<Transaction>,
    ) -> Result<(), BlockchainError> {
        let environments = ContractEnvironments::default();
        let hash = Arc::new(tx.hash());
        let size = tx.size();
        mempool.add_tx(storage, &environments, 0, 0, FEE_PER_KB, 0, hash, tx, size, BlockVersion::V6).await
    }

    async fn add_tx_to_mempool_internal_with_size(
        mempool: &mut Mempool,
        storage: &MemoryStorage,
        tx: Arc<Transaction>,
        size: usize,
    ) -> Result<(), BlockchainError> {
        let hash = Arc::new(tx.hash());
        mempool.add_tx_internal(storage, 0, hash, tx, size, BlockVersion::V6, HashMap::new(), None).await
    }

    async fn cleanup_mempool(
        mempool: &mut Mempool,
        storage: &MemoryStorage,
    ) -> Result<Vec<(Arc<Hash>, SortedTx)>, BlockchainError> {
        let environments = ContractEnvironments::default();
        mempool.clean_up(storage, &environments, 0, 0, BlockVersion::V6, FEE_PER_KB, 0, false).await
    }

    #[tokio::test]
    async fn test_mempool_memory_limit_large_limit_keeps_all_txs() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let mut bob = TrackedAccount::new();
        bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &bob).await;

        let carol = TrackedAccount::new();
        let tx_a = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("alice tx failed"));
        let tx_b = Arc::new(create_transfer_tx_for_account(
            &mut bob,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("bob tx failed"));
        let expected_memory = tx_a.size() + tx_b.size();

        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
        add_tx_to_mempool(&mut mempool, &storage, tx_a).await.unwrap();
        add_tx_to_mempool(&mut mempool, &storage, tx_b).await.unwrap();

        assert_eq!(mempool.size(), 2);
        assert_eq!(mempool.memory_usage(), expected_memory);
    }

    #[tokio::test]
    async fn test_mempool_memory_limit_below_single_tx_rejects_added_tx() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            bob.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("transfer tx failed"));
        let hash = tx.hash();

        let mut mempool = Mempool::new(Network::Devnet, false, 0, 0);
        let err = add_tx_to_mempool(&mut mempool, &storage, tx).await
            .expect_err("tx should be rejected when limit cannot keep it");

        assert!(matches!(err, BlockchainError::MempoolMemoryLimit));
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.memory_usage(), 0);
        assert!(!mempool.contains_tx(&hash));
        assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
        assert!(mempool.ordered_by_fee.is_empty());
    }

    #[tokio::test]
    async fn test_mempool_memory_limit_exact_limit_keeps_txs() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let mut bob = TrackedAccount::new();
        bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &bob).await;

        let carol = TrackedAccount::new();
        let tx_a = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("alice tx failed"));
        let tx_b = Arc::new(create_transfer_tx_for_account(
            &mut bob,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("bob tx failed"));
        let tx_a_size = tx_a.size();
        let tx_b_size = tx_b.size();

        let mut mempool = Mempool::new(Network::Devnet, false, 0, (tx_a_size + tx_b_size) as u64);
        add_tx_to_mempool(&mut mempool, &storage, tx_a).await.unwrap();
        add_tx_to_mempool(&mut mempool, &storage, tx_b).await.unwrap();

        assert_eq!(mempool.size(), 2);
        assert_eq!(mempool.memory_usage(), tx_a_size + tx_b_size);
    }

    #[tokio::test]
    async fn test_mempool_memory_limit_evicts_lowest_fee_rate_first() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let mut bob = TrackedAccount::new();
        bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &bob).await;

        let carol = TrackedAccount::new();
        let low_fee_tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("low fee tx failed"));
        let high_fee_tx = Arc::new(create_transfer_tx_for_account(
            &mut bob,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("high fee tx failed"));
        let low_hash = low_fee_tx.hash();
        let high_hash = high_fee_tx.hash();
        let low_size = low_fee_tx.size() + 2048;
        let high_size = high_fee_tx.size();

        let mut mempool = Mempool::new(Network::Devnet, false, 0, low_size as u64);
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, low_fee_tx, low_size).await.unwrap();
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, high_fee_tx, high_size).await.unwrap();

        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.memory_usage(), high_size);
        assert!(!mempool.contains_tx(&low_hash));
        assert!(mempool.contains_tx(&high_hash));
        assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
        assert!(mempool.get_cache_for(&bob.get_public_key()).is_some());
    }

    #[tokio::test]
    async fn test_mempool_memory_limit_rejects_new_low_fee_tx_and_keeps_existing() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let mut bob = TrackedAccount::new();
        bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &bob).await;

        let carol = TrackedAccount::new();
        let existing_tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("existing tx failed"));
        let new_low_fee_tx = Arc::new(create_transfer_tx_for_account(
            &mut bob,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("new low fee tx failed"));
        let existing_hash = existing_tx.hash();
        let new_hash = new_low_fee_tx.hash();
        let existing_size = existing_tx.size();
        let new_low_fee_size = new_low_fee_tx.size() + 4096;

        let mut mempool = Mempool::new(Network::Devnet, false, 0, existing_size as u64);
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, existing_tx, existing_size).await.unwrap();
        let err = add_tx_to_mempool_internal_with_size(&mut mempool, &storage, new_low_fee_tx, new_low_fee_size).await
            .expect_err("new low-fee TX should be evicted and rejected");

        assert!(matches!(err, BlockchainError::MempoolMemoryLimit));
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.memory_usage(), existing_size);
        assert!(mempool.contains_tx(&existing_hash));
        assert!(!mempool.contains_tx(&new_hash));
        assert!(mempool.get_cache_for(&alice.get_public_key()).is_some());
        assert!(mempool.get_cache_for(&bob.get_public_key()).is_none());
    }

    #[tokio::test]
    async fn test_mempool_memory_limit_evicts_multiple_low_fee_accounts() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let mut bob = TrackedAccount::new();
        bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &bob).await;

        let mut carol = TrackedAccount::new();
        carol.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &carol).await;

        let destination = TrackedAccount::new();
        let low_fee_tx_a = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            destination.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("first low fee tx failed"));
        let low_fee_tx_b = Arc::new(create_transfer_tx_for_account(
            &mut bob,
            destination.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("second low fee tx failed"));
        let high_fee_tx = Arc::new(create_transfer_tx_for_account(
            &mut carol,
            destination.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("high fee tx failed"));

        let low_hash_a = low_fee_tx_a.hash();
        let low_hash_b = low_fee_tx_b.hash();
        let high_hash = high_fee_tx.hash();
        let low_size_a = low_fee_tx_a.size() + 4096;
        let low_size_b = low_fee_tx_b.size() + 4096;
        let high_size = high_fee_tx.size();

        let mut mempool = Mempool::new(Network::Devnet, false, 0, high_size as u64);
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, low_fee_tx_a.clone(), low_size_a).await
            .expect_err("first oversized low-fee TX should not fit by itself");

        // Use a fresh pool so we can verify multi-eviction after two low-fee accounts are already present.
        let mut mempool = Mempool::new(Network::Devnet, false, 0, (low_size_a + low_size_b + high_size) as u64);
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, low_fee_tx_b.clone(), low_size_b).await.unwrap();
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, low_fee_tx_a.clone(), low_size_a).await.unwrap();
        mempool.max_memory_usage = high_size as u64;
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, high_fee_tx, high_size).await.unwrap();

        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.memory_usage(), high_size);
        assert!(!mempool.contains_tx(&low_hash_a));
        assert!(!mempool.contains_tx(&low_hash_b));
        assert!(mempool.contains_tx(&high_hash));
        assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
        assert!(mempool.get_cache_for(&bob.get_public_key()).is_none());
        assert!(mempool.get_cache_for(&carol.get_public_key()).is_some());
    }

    #[tokio::test]
    async fn test_mempool_memory_limit_evicts_whole_nonce_chain() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let mut bob = TrackedAccount::new();
        bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &bob).await;

        let carol = TrackedAccount::new();
        let alice_first_tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("alice first tx failed"));
        let alice_second_tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("alice second tx failed"));
        let bob_tx = Arc::new(create_transfer_tx_for_account(
            &mut bob,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("bob tx failed"));

        let alice_first_hash = alice_first_tx.hash();
        let alice_second_hash = alice_second_tx.hash();
        let bob_hash = bob_tx.hash();

        let alice_first_size = alice_first_tx.size() + 4096;
        let alice_second_size = alice_second_tx.size() + 4096;
        let bob_size = bob_tx.size();

        let mut mempool = Mempool::new(Network::Devnet, false, 0, (alice_first_size + alice_second_size) as u64);
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, alice_first_tx, alice_first_size).await.unwrap();
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, alice_second_tx, alice_second_size).await.unwrap();
        add_tx_to_mempool_internal_with_size(&mut mempool, &storage, bob_tx, bob_size).await.unwrap();

        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.memory_usage(), bob_size);
        assert!(!mempool.contains_tx(&alice_first_hash));
        assert!(!mempool.contains_tx(&alice_second_hash));
        assert!(mempool.contains_tx(&bob_hash));
        assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
        assert!(mempool.get_cache_for(&bob.get_public_key()).is_some());
    }

    #[tokio::test]
    async fn test_mempool_expiration_disabled_keeps_old_tx() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            bob.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("transfer tx failed"));
        let hash = Arc::new(tx.hash());

        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);
        add_tx_to_mempool(&mut mempool, &storage, tx).await.unwrap();
        mempool.txs.get_mut(&hash).unwrap().first_seen = get_current_time_in_seconds().saturating_sub(3600);

        let deleted = cleanup_mempool(&mut mempool, &storage).await.unwrap();

        assert!(deleted.is_empty());
        assert_eq!(mempool.size(), 1);
        assert!(mempool.contains_tx(&hash));
    }

    #[tokio::test]
    async fn test_mempool_expiration_removes_expired_tx() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            bob.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("transfer tx failed"));
        let hash = Arc::new(tx.hash());

        let mut mempool = Mempool::new(Network::Devnet, false, 1, u64::MAX);
        add_tx_to_mempool(&mut mempool, &storage, tx).await.unwrap();
        mempool.txs.get_mut(&hash).unwrap().first_seen = get_current_time_in_seconds().saturating_sub(2);

        let deleted = cleanup_mempool(&mut mempool, &storage).await.unwrap();

        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].0, hash);
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.memory_usage(), 0);
        assert!(!mempool.contains_tx(&hash));
        assert!(mempool.ordered_by_fee.is_empty());
    }

    #[tokio::test]
    async fn test_mempool_expiration_keeps_fresh_account() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let mut bob = TrackedAccount::new();
        bob.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &bob).await;

        let carol = TrackedAccount::new();
        let expired_tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("expired tx failed"));
        let fresh_tx = Arc::new(create_transfer_tx_for_account(
            &mut bob,
            carol.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("fresh tx failed"));
        let expired_hash = Arc::new(expired_tx.hash());
        let fresh_hash = Arc::new(fresh_tx.hash());
        let fresh_size = fresh_tx.size();

        let mut mempool = Mempool::new(Network::Devnet, false, 10, u64::MAX);
        add_tx_to_mempool(&mut mempool, &storage, expired_tx).await.unwrap();
        add_tx_to_mempool(&mut mempool, &storage, fresh_tx).await.unwrap();
        mempool.txs.get_mut(&expired_hash).unwrap().first_seen = get_current_time_in_seconds().saturating_sub(10);

        let deleted = cleanup_mempool(&mut mempool, &storage).await.unwrap();

        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].0, expired_hash);
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.memory_usage(), fresh_size);
        assert!(!mempool.contains_tx(&expired_hash));
        assert!(mempool.contains_tx(&fresh_hash));
    }

    #[tokio::test]
    async fn test_mempool_expiration_removes_nonce_chain_after_expired_head() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, 100 * COIN_VALUE);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let first_tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            bob.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("first tx failed"));
        let second_tx = Arc::new(create_transfer_tx_for_account(
            &mut alice,
            bob.address(),
            COIN_VALUE,
            None,
            TxVersion::V2,
            make_reference(),
        ).expect("second tx failed"));
        let first_hash = Arc::new(first_tx.hash());
        let second_hash = Arc::new(second_tx.hash());

        let mut mempool = Mempool::new(Network::Devnet, false, 10, u64::MAX);
        add_tx_to_mempool(&mut mempool, &storage, first_tx).await.unwrap();
        add_tx_to_mempool(&mut mempool, &storage, second_tx).await.unwrap();
        mempool.txs.get_mut(&first_hash).unwrap().first_seen = get_current_time_in_seconds().saturating_sub(10);

        let deleted = cleanup_mempool(&mut mempool, &storage).await.unwrap();
        let deleted_hashes: IndexSet<_> = deleted.into_iter()
            .map(|(hash, _)| hash)
            .collect();

        assert_eq!(deleted_hashes.len(), 2);
        assert!(deleted_hashes.contains(&first_hash));
        assert!(deleted_hashes.contains(&second_hash));
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.memory_usage(), 0);
        assert!(mempool.get_cache_for(&alice.get_public_key()).is_none());
        assert!(mempool.ordered_by_fee.is_empty());
    }

    /// A MultiSig setup TX (configuring multisig on `alice`) should be accepted by the mempool.
    #[tokio::test]
    async fn test_multisig_setup_tx() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let carol = TrackedAccount::new();

        let participants = vec![bob.address(), carol.address()];
        let tx = create_multisig_setup_tx(&mut alice, participants, 2, &[]);
        let result = add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await;
        assert!(result.is_ok(), "multisig setup TX should be accepted: {:?}", result.err());
    }

    /// A transfer from an account with multisig configured in storage should be accepted
    /// when the TX carries the correct multisig signatures.
    #[tokio::test]
    async fn test_transfer_with_valid_multisig() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let carol = TrackedAccount::new();

        // Pre-configure alice's account with 2-of-2 multisig (bob=0, carol=1)
        let payload = MultiSigPayload {
            threshold: 2,
            participants: [bob.get_public_key(), carol.get_public_key()].into_iter().collect(),
        };
        setup_multisig_in_storage(&mut storage, &alice, payload).await;

        // (id=0 => bob, id=1 => carol)
        let tx = create_multisig_transfer_tx(&mut alice, bob.address(), COIN_VALUE, &[(0, &bob), (1, &carol)], TxVersion::V2, make_reference());
        let result = add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await;
        assert!(result.is_ok(), "transfer with valid multisig should be accepted: {:?}", result.err());
    }

    /// A transfer from a multisig-configured account that carries NO multisig field
    /// should be rejected with `MultiSigNotFound`.
    #[tokio::test]
    async fn test_transfer_without_multisig_fails() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let carol = TrackedAccount::new();

        let payload = MultiSigPayload {
            threshold: 2,
            participants: [bob.get_public_key(), carol.get_public_key()].into_iter().collect(),
        };
        setup_multisig_in_storage(&mut storage, &alice, payload).await;

        // Normal transfer: no multisig signatures attached
        let tx = create_transfer_tx_for_account(
            &mut alice, bob.address(), COIN_VALUE, None, TxVersion::V2, make_reference()
        ).unwrap();

        let err = add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await.unwrap_err();
        assert!(
            matches!(err, BlockchainError::VerificationError(VerificationError::MultiSigNotFound)),
            "expected MultiSigNotFound, got: {:?}", err
        );
    }

    /// A transfer from a multisig account with fewer signatures than the threshold
    /// should be rejected with `MultiSigParticipants`.
    #[tokio::test]
    async fn test_transfer_with_wrong_sig_count_fails() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let carol = TrackedAccount::new();

        // threshold=2 but we'll only attach 1 signature
        let payload = MultiSigPayload {
            threshold: 2,
            participants: [bob.get_public_key(), carol.get_public_key()].into_iter().collect(),
        };
        setup_multisig_in_storage(&mut storage, &alice, payload).await;

        // Only sign with bob (id=0), missing carol
        let tx = create_multisig_transfer_tx(&mut alice, bob.address(), COIN_VALUE, &[(0, &bob)], TxVersion::V2, make_reference());
        let err = add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await.unwrap_err();
        assert!(
            matches!(err, BlockchainError::VerificationError(VerificationError::MultiSigParticipants)),
            "expected MultiSigParticipants, got: {:?}", err
        );
    }

    /// A transfer from an account WITHOUT multisig configured but carrying a multisig field
    /// should be rejected with `MultiSigNotConfigured`.
    #[tokio::test]
    async fn test_tx_with_multisig_but_not_configured_fails() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();

        // No multisig configured in storage for alice.
        // Create a transfer TX with multisig sigs (as if alice had 1-of-1 multisig with bob).
        let tx = create_multisig_transfer_tx(&mut alice, bob.address(), COIN_VALUE, &[(0, &bob)], TxVersion::V2, make_reference());
        let err = add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await.unwrap_err();
        assert!(
            matches!(err, BlockchainError::VerificationError(VerificationError::MultiSigNotConfigured)),
            "expected MultiSigNotConfigured, got: {:?}", err
        );
    }

    /// A delete/reset multisig TX (threshold=0, no participants) from an account that HAS multisig
    /// configured should be accepted.
    #[tokio::test]
    async fn test_multisig_delete_tx() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();

        // Configure multisig first
        let payload = MultiSigPayload {
            threshold: 1,
            participants: [bob.get_public_key()].into_iter().collect(),
        };
        setup_multisig_in_storage(&mut storage, &alice, payload).await;

        // Delete multisig: threshold=0, no participants — but bob must co-sign since threshold=1
        let delete_tx = create_multisig_setup_tx(&mut alice, vec![], 0, &[(0, &bob)]);
        let result = add_tx_to_mempool(&mut mempool, &storage, Arc::new(delete_tx)).await;
        assert!(result.is_ok(), "multisig delete TX should be accepted: {:?}", result.err());
    }

    /// A delete/reset multisig TX from an account that does NOT have multisig configured
    /// should be rejected with `MultiSigNotConfigured`.
    #[tokio::test]
    async fn test_multisig_delete_without_config_fails() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
        setup_account(&mut storage, &alice).await;

        // No multisig configured — try to delete/reset
        let delete_tx = create_multisig_setup_tx(&mut alice, vec![], 0, &[]);
        let err = add_tx_to_mempool(&mut mempool, &storage, Arc::new(delete_tx)).await.unwrap_err();
        assert!(
            matches!(err, BlockchainError::VerificationError(VerificationError::MultiSigNotConfigured)),
            "expected MultiSigNotConfigured, got: {:?}", err
        );
    }

    /// After setting up multisig via TX and then deleting it via a follow-up TX, subsequent
    /// normal transfers (without multisig sigs) should be accepted again.
    #[tokio::test]
    async fn test_multisig_setup_then_delete_allows_normal_transfer() {
        let mut storage = MemoryStorage::new(Network::Devnet, 1);
        let mut mempool = Mempool::new(Network::Devnet, false, 0, u64::MAX);

        let mut alice = TrackedAccount::new();
        alice.set_balance(XELIS_ASSET, COIN_VALUE * 100);
        setup_account(&mut storage, &alice).await;

        let bob = TrackedAccount::new();
        let carol = TrackedAccount::new();

        // 1. Setup multisig (1-of-1 with bob)
        let setup_tx = create_multisig_setup_tx(&mut alice, vec![bob.address()], 1, &[]);
        add_tx_to_mempool(&mut mempool, &storage, Arc::new(setup_tx)).await.unwrap();

        // 2. Delete multisig — alice now has 1-of-1 multisig (bob), so bob must co-sign the delete TX
        let delete_tx = create_multisig_setup_tx(&mut alice, vec![], 0, &[(0, &bob)]);
        add_tx_to_mempool(&mut mempool, &storage, Arc::new(delete_tx)).await.unwrap();

        // 3. Normal transfer: no multisig signatures needed (multisig is now deleted in cache)
        let tx = create_transfer_tx_for_account(
            &mut alice, carol.address(), COIN_VALUE, None, TxVersion::V2, make_reference()
        ).unwrap();
        let result = add_tx_to_mempool(&mut mempool, &storage, Arc::new(tx)).await;
        assert!(result.is_ok(), "normal transfer after multisig delete should be accepted: {:?}", result.err());
    }
}
