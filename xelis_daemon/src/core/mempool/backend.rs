use crate::core::{
    error::BlockchainError,
    state::{ChainState, MempoolProvider},
    storage::Storage,
    TxCache,
    blockchain::{ContractEnvironments, estimate_tx_fee_per_kb},
};
use std::{collections::{BTreeSet, HashMap}, sync::{Arc, Weak, Mutex, atomic::Ordering as AtomicOrdering}, mem};
use linked_hash_table::{LinkedHashMap, LinkedHashSet};
use indexmap::IndexSet;
use log::{debug, trace, warn};
use xelis_common::{
    api::daemon::FeeRatesEstimated,
    block::{BlockVersion, TopoHeight},
    config::FEE_PER_KB,
    crypto::{elgamal::Ciphertext, Hash, PublicKey},
    network::Network,
    serializer::Serializer,
    time::get_current_time_in_seconds,
    transaction::{MultiSigPayload, Transaction},
};
use super::{AccountCache, SortedTx, VerifiedTransaction};
use super::sender::{SenderLocks, SenderVerification};
use super::fee_entry::TxFeeEntry;

/// Stored transactions and all derived indexes for the pending pool.
/// Shared admission mutates this state under the internal write lock; exclusive
/// maintenance accesses it through `RwLock::get_mut`. Sender cache changes
/// invalidate active snapshots, including when another sender triggers eviction.
pub struct MempoolBackend {
    /// Shared gate registry used to invalidate active sender snapshots.
    pub(super) sender_locks: SenderLocks,
    /// Network flag used when displaying account addresses in errors and logs.
    pub(super) mainnet: bool,
    /// Transactions in insertion order for nonce-preserving P2P propagation.
    pub(super) txs: LinkedHashMap<Arc<Hash>, SortedTx>,
    /// Expected nonce, spending balances and multisig state for each sender.
    pub(super) caches: HashMap<PublicKey, AccountCache>,
    /// Whether verification must bypass the static proof cache.
    pub(super) disable_zkp_cache: bool,
    /// Maximum pending age in seconds; zero disables expiration.
    pub(super) tx_expiration_time: u64,
    /// Maximum sum of serialized transaction sizes before whole-account eviction.
    pub(super) max_memory_usage: u64,
    /// Running sum of stored transaction sizes, excluding allocator and index overhead.
    pub(super) memory_usage: usize,
    /// Ascending fee index whose first entry identifies a cheapest transaction.
    pub(super) ordered_by_fee: BTreeSet<TxFeeEntry>,
}

impl MempoolBackend {
    /// Create empty storage and indexes with the configured verification and eviction limits.
    pub fn new(network: Network, disable_zkp_cache: bool, tx_expiration_time: u64, max_memory_usage: u64) -> Self {
        Self {
            sender_locks: Arc::new(Mutex::new(HashMap::new())),
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

    /// Commit verified sender state only if its snapshot revision is current.
    /// Return `MempoolCacheChanged` if eviction invalidated the snapshot. Reject
    /// duplicate hashes and mismatched sender leases before mutating the backend.
    /// The caller holds backend write access and retains the owned sender permit.
    pub(super) fn store_verified(&mut self, verification: &SenderVerification, verified: VerifiedTransaction) -> Result<(), BlockchainError> {
        if !verification.is_current() {
            return Err(BlockchainError::MempoolCacheChanged)
        }

        if self.contains_tx(&verified.hash) {
            return Err(BlockchainError::TxAlreadyInMempool(verified.hash.as_ref().clone()))
        }

        if verified.tx.get_source() != &verification.lease.source {
            return Err(BlockchainError::MempoolSenderMismatch)
        }

        self.store_tx(verified.hash, verified.tx, verified.size, verified.fees, verified.balances, verified.multisig)
    }

    /// Invalidate any active verification based on this sender's previous cache.
    /// Called with backend write or exclusive lifecycle access. It does not wait
    /// for the sender permit, allowing eviction without cross-sender deadlocks.
    fn invalidate_sender(&self, source: &PublicKey) {
        let registry = self.sender_locks.lock().expect("sender lock registry poisoned");
        if let Some(lock) = registry.get(source).and_then(Weak::upgrade) {
            lock.revision.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    /// Average descending fee rates in high (30%), normal (40%) and remaining groups.
    /// Clamp each estimate to the base fee; small or empty samples use that base fee.
    pub(super) fn internal_estimate_fee_rates(mut fee_rates: Vec<u64>, base_fee: u64) -> FeeRatesEstimated {
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

    /// Estimate priority fee rates from currently stored transactions.
    /// Uses group averages rather than medians and keeps the protocol default fee.
    pub fn estimate_fee_rates(&self, base_fee: u64) -> Result<FeeRatesEstimated, BlockchainError> { 
        let fee_rates: Vec<_> = self.txs.values()
            .map(SortedTx::get_fee_per_kb)
            .collect();

        Ok(Self::internal_estimate_fee_rates(fee_rates, base_fee))
    }

    /// Verify and add a TX while holding exclusive lifecycle access.
    /// Normal admissions use Mempool::add_tx to verify different senders concurrently.
    #[inline]
    pub(super) async fn add_tx<S: Storage>(
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
            cache: self.get_cache_for(tx.get_source()).map(|c| (tx.get_source(), c)),
            storage
        };
        let mut state = ChainState::new(&provider, environments, stable_topoheight, topoheight, topoheight, block_version, tx_base_fee, base_height);
        let tx_cache = TxCache::new(storage, &*self, self.disable_zkp_cache);
        tx.verify(&hash, &mut state, &tx_cache).await?;

        let (balances, multisig) = state.get_sender_cache(tx.get_source())
            .ok_or_else(|| BlockchainError::AccountNotFound(tx.get_source().as_address(self.mainnet)))?;

        self.add_tx_internal(storage, stable_topoheight, hash, tx, size, block_version, balances, multisig).await
    }

    /// Add a transaction already known by local storage back to the mempool.
    /// Static proofs may only be skipped through the hash-bound storage cache.
    pub(super) async fn add_known_tx<S: Storage>(
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
        self.add_tx(storage, environments, stable_topoheight, topoheight, tx_base_fee, base_height, hash, tx, size, block_version).await
    }

    /// Estimate fees and insert a transaction with already-verified sender state.
    /// The caller must supply balances and multisig produced by verification.
    pub(super) async fn add_tx_internal<S: Storage>(
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
        let fees = estimate_tx_fee_per_kb(storage, stable_topoheight, &tx, size, block_version).await?;
        self.store_tx(hash, tx, size, fees, balances, multisig)
    }

    /// Update the sender cache, insertion map, fee index and size accounting together.
    /// Enforce the memory limit by evicting entire sender sequences. Return
    /// `MempoolMemoryLimit` if the newly inserted transaction is itself evicted.
    pub(super) fn store_tx(
        &mut self,
        hash: Arc<Hash>,
        tx: Arc<Transaction>,
        size: usize,
        (fee_per_kb, fee_limit_per_kb): (u64, u64),
        balances: HashMap<Hash, Ciphertext>,
        multisig: Option<MultiSigPayload>,
    ) -> Result<(), BlockchainError> {
        let nonce = tx.get_nonce();
        self.invalidate_sender(tx.get_source());
        debug!("fee per kb {} for TX {}", fee_per_kb, hash);

        // update the cache for this owner
        if let Some(cache) = self.caches.get_mut(tx.get_source()) {
            // Extend the sender sequence with the verified transaction hash
            debug!("Cache found for owner {} with nonce range {}-{}, nonce = {}", tx.get_source().as_address(self.mainnet), cache.get_min(), cache.get_max(), nonce);
            cache.update(nonce, hash.clone());

            // Update re-computed balances
            cache.update_balances(balances);
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

    /// Evict accounts containing cheapest transactions until the size limit is satisfied.
    /// Removing the whole sender sequence avoids leaving dependent nonces behind.
    /// Invalidate active snapshots before dropping their cached predecessors.
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

            self.invalidate_sender(&source);
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

    /// Borrow the expected state of all senders with pending transactions.
    pub fn get_caches(&self) -> &HashMap<PublicKey, AccountCache> {
        &self.caches
    }

    /// Check transaction membership by hash.
    pub fn contains_tx(&self, hash: &Hash) -> bool {
        self.txs.contains_key(hash)
    }

    /// Borrow a transaction and its cached metadata, or return `TxNotFound`.
    pub fn get_sorted_tx(&self, hash: &Hash) -> Result<&SortedTx, BlockchainError> {
        self.txs.get(hash)
            .ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))
    }

    /// Clone the shared transaction handle for a hash, or return `TxNotFound`.
    pub fn get_tx(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        let tx = self.get_sorted_tx(hash)?;
        Ok(Arc::clone(tx.get_tx()))
    }

    /// Borrow a shared transaction handle without cloning it, or return `TxNotFound`.
    pub fn view_tx<'a>(&'a self, hash: &Hash) -> Result<&'a Arc<Transaction>, BlockchainError> {
        if let Some(sorted_tx) = self.txs.get(hash) {
            return Ok(sorted_tx.get_tx())
        }

        Err(BlockchainError::TxNotFound(hash.clone()))
    }

    /// Borrow all pending transactions in insertion order.
    pub fn get_txs(&self) -> &LinkedHashMap<Arc<Hash>, SortedTx> {
        &self.txs
    }

    /// Borrow the expected pending state for a sender, if it has a cache.
    pub fn get_cache_for(&self, key: &PublicKey) -> Option<&AccountCache> {
        self.caches.get(key)
    }

    /// Return the number of currently stored transactions.
    pub fn size(&self) -> usize {
        self.txs.len()
    }

    /// Return the sum of stored serialized transaction sizes in bytes.
    pub fn memory_usage(&self) -> usize {
        self.memory_usage
    }

    /// Return the configured limit on stored serialized transaction sizes in bytes.
    pub fn get_max_memory_usage(&self) -> u64 {
        self.max_memory_usage
    }

    /// Clear transactions, sender caches and fee indexes, and reset size accounting.
    /// Requires exclusive lifecycle access so no shared admission snapshot survives.
    pub(super) fn clear(&mut self) {
        self.txs.clear();
        self.caches.clear();
        self.memory_usage = 0;
        self.ordered_by_fee.clear();
    }

    /// Take all transactions in insertion order and reset sender caches and indexes.
    /// Requires exclusive lifecycle access so no shared admission snapshot survives.
    pub(super) fn drain(&mut self) -> Vec<(Hash, Arc<Transaction>)> {
        let mut txs = Vec::with_capacity(self.txs.len());
        for (hash, sorted_tx) in self.txs.drain() {
            txs.push((hash.as_ref().clone(), sorted_tx.consume()));
        }

        self.caches.clear();
        self.memory_usage = 0;
        self.ordered_by_fee.clear();

        txs
    }

    /// Load orphaned transactions and merge them with pending entries for each sender.
    /// Re-verify the merged sequences and return transactions that fail reinsertion.
    pub(super) async fn try_add_back_txs<S: Storage>(
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

    /// Reconcile every sender sequence with the current chain nonce and state.
    /// Check the first remaining transaction when a sequence changes or `full` is
    /// set, remove incompatible or expired sequences, then enforce the memory limit.
    /// Return all removed transaction hashes and metadata under exclusive lifecycle access.
    pub(super) async fn clean_up<S: Storage>(
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

                    let tx_cache = TxCache::new(storage, &*self, self.disable_zkp_cache);
                    if let Some((next_tx, tx_hash)) = first_tx {
                        let provider = MempoolProvider {
                            cache: None,
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

}
