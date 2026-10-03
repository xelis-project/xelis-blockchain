//! Pending transactions with serialized admission per sender and parallel verification across senders.
//!
//! Sender snapshots contain nonce, spending balances and multisig changes only;
//! receiver changes are read from chain storage. Verification releases the backend
//! lock, then commits all indexes and the sender cache under one write guard.
//!
//! Blockchain keeps shared lifecycle access and a stable storage view throughout
//! admission. Cleanup, reorg reinsertion and other `&mut self` operations use
//! exclusive lifecycle access. Memory eviction can occur during verification and
//! invalidates affected sender snapshots through their revisions.

mod account_cache;
mod backend;
mod fee_entry;
mod sender;
mod sorted_tx;

#[cfg(test)]
mod tests;

pub use account_cache::AccountCache;
pub use backend::MempoolBackend;
pub use sorted_tx::SortedTx;

use sender::{SenderLock, SenderLocks, SenderLease, SenderVerification};
use crate::core::{
    error::BlockchainError,
    state::{ChainState, MempoolProvider},
    storage::Storage,
    TxCache,
    blockchain::{ContractEnvironments, estimate_tx_fee_per_kb},
};
use std::{collections::HashMap, sync::{Arc, Weak, atomic::AtomicU64}};
use tokio::sync::{RwLock, RwLockReadGuard, Semaphore};
use log::info;
use xelis_common::{
    block::{BlockVersion, TopoHeight},
    crypto::{elgamal::Ciphertext, Hash, PublicKey},
    network::Network,
    transaction::{MultiSigPayload, Transaction},
};

/// Transaction metadata and resulting sender state awaiting an atomic commit.
/// The matching sender permit and snapshot revision are checked before insertion.
struct VerifiedTransaction {
    /// Hash identifying the transaction and its static proof cache entry.
    hash: Arc<Hash>,
    /// Verified transaction whose source must match the sender lease.
    tx: Arc<Transaction>,
    /// Serialized transaction size in bytes for memory accounting.
    size: usize,
    /// Fee and fee-limit rates per rounded kilobyte, excluding extra fees.
    fees: (u64, u64),
    /// Expected spending balances for assets loaded by this verification.
    balances: HashMap<Hash, Ciphertext>,
    /// Expected sender multisig configuration after this transaction.
    multisig: Option<MultiSigPayload>,
}

/// Coordinates sender admission and owns the locked transaction backend.
/// Shared admissions use sender permits; mutable maintenance operations have
/// exclusive access and can use the backend without acquiring its lock.
pub struct Mempool {
    /// Transactions, sender caches and indexes updated together under a write guard.
    backend: RwLock<MempoolBackend>,
    /// Shared registry keeping one semaphore alive per active sender.
    sender_locks: SenderLocks,
}

impl Mempool {
    /// Create an empty mempool with proof-cache, expiration and memory-limit settings.
    /// A zero expiration time disables age-based eviction; sizes are tracked in bytes.
    pub fn new(network: Network, disable_zkp_cache: bool, tx_expiration_time: u64, max_memory_usage: u64) -> Self {
        let backend = MempoolBackend::new(network, disable_zkp_cache, tx_expiration_time, max_memory_usage);
        let sender_locks = Arc::clone(&backend.sender_locks);
        Self { backend: RwLock::new(backend), sender_locks }
    }

    /// Borrow a consistent backend view for transaction and cache queries.
    /// The returned guard blocks commits until dropped. Release it before admission
    /// or any operation that needs the backend write lock.
    pub async fn read(&self) -> RwLockReadGuard<'_, MempoolBackend> {
        self.backend.read().await
    }

    /// Check whether a transaction is already pending in the mempool.
    pub async fn contains_tx(&self, hash: &Hash) -> bool {
        self.backend.read().await.contains_tx(hash)
    }

    /// Return the current number of pending transactions using a short internal read lock.
    pub async fn size(&self) -> usize {
        self.backend.read().await.size()
    }

    /// Discard all pending transactions, sender caches and fee indexes.
    pub fn clear(&mut self) {
        self.backend.get_mut().clear();
    }

    /// Take all pending transactions in insertion order and reset cached state.
    /// Returns each hash with its shared transaction without re-verifying it.
    pub fn drain(&mut self) -> Vec<(Hash, Arc<Transaction>)> {
        self.backend.get_mut().drain()
    }

    /// Re-verify and reinsert a transaction already known by local storage.
    /// Only the hash-bound proof cache may skip static proofs; nonce, balances and
    /// multisig are still checked against the current state.
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
        self.backend.get_mut().add_known_tx(storage, environments, stable_topoheight, topoheight, tx_base_fee, base_height, hash, tx, size, block_version).await
    }

    /// Reinsert transactions orphaned by a chain reorganization.
    /// Merge them with existing transactions from each affected sender and verify
    /// the merged sequences. Return the transactions that could not be reinserted.
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
        self.backend.get_mut().try_add_back_txs(storage, transactions, environments, stable_topoheight, topoheight, block_version, tx_base_fee, base_height).await
    }

    /// Reconcile pending sender sequences with the current chain state.
    /// Remove invalid, expired or low-fee entries selected by memory eviction and
    /// return their hashes and metadata. `full` also checks unchanged sequences.
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
        self.backend.get_mut().clean_up(storage, environments, stable_topoheight, topoheight, block_version, tx_base_fee, base_height, full).await
    }

    /// Stop the mempool by clearing all pending transactions and cached state.
    pub async fn stop(&mut self) {
        info!("Stopping mempool...");
        self.clear();
    }

    /// Find or create the sender semaphore and retain it through admission.
    /// The registry mutex protects lookup and creation only; it is never held
    /// while awaiting a permit, reading storage or verifying a transaction.
    fn sender_lease(&self, source: &PublicKey) -> SenderLease {
        let mut registry = self.sender_locks.lock().expect("sender lock registry poisoned");
        let lock = registry.get(source).and_then(Weak::upgrade).unwrap_or_else(|| {
            let lock = Arc::new(SenderLock {
                semaphore: Arc::new(Semaphore::new(1)),
                revision: AtomicU64::new(0),
            });
            registry.insert(source.clone(), Arc::downgrade(&lock));
            lock
        });
        SenderLease { source: source.clone(), lock: Some(lock), registry: Arc::clone(&self.sender_locks) }
    }

    /// Acquire the sender's single owned permit without holding a backend guard.
    /// The initial revision is a placeholder; admission captures the current
    /// revision together with the cache snapshot after obtaining this permit.
    async fn begin_verification(&self, source: &PublicKey) -> SenderVerification {
        let lease = self.sender_lease(source);
        let permit = Arc::clone(&lease.lock().semaphore).acquire_owned().await
            .expect("sender semaphore is never closed");
        SenderVerification { _permit: permit, lease, revision: 0 }
    }

    /// Verify a transaction against its sender snapshot, then atomically commit it.
    /// The sender permit stays held through verification and insertion. Other
    /// senders can verify concurrently; backend guards are limited to snapshot
    /// reads and commit. If eviction invalidates the snapshot, return an error.
    /// Return insertion metadata captured under the commit lock so notifications
    /// remain available even if a later admission evicts this transaction.
    /// The caller must keep the chain storage view stable until admission finishes.
    pub async fn add_tx<S: Storage>(
        &self,
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
    ) -> Result<SortedTx, BlockchainError> {
        let mut verification = self.begin_verification(tx.get_source()).await;

        // Snapshot AFTER acquiring the permit, so a previous admission's
        // nonce, balances and multisig are included consistently.
        let (cache, revision, mainnet, disabled) = {
            let backend = self.backend.read().await;
            if backend.contains_tx(&hash) {
                return Err(BlockchainError::TxAlreadyInMempool(hash.as_ref().clone()))
            }

            let cache = backend.get_cache_for(tx.get_source());
            if let Some(cache) = cache {
                if cache.has_tx_with_same_nonce(tx.get_nonce()) {
                    return Err(BlockchainError::TxNonceAlreadyUsed(tx.get_nonce()))
                }

                if !(tx.get_nonce() <= cache.get_max() + 1 && tx.get_nonce() >= cache.get_min()) {
                    return Err(BlockchainError::InvalidTxNonceMempoolCache(tx.get_nonce(), cache.get_min(), cache.get_max()))
                }
            }

            (cache.cloned(), verification.revision_expected(), backend.mainnet, backend.disable_zkp_cache)
        };

        verification.revision = revision;
        let provider = MempoolProvider {
            cache: cache.as_ref().map(|c| (tx.get_source(), c)),
            storage,
        };

        let mut state = ChainState::new(&provider, environments, stable_topoheight, topoheight, topoheight, block_version, tx_base_fee, base_height);
        let tx_cache = TxCache::new(storage, &*self, disabled);
        tx.verify(&hash, &mut state, &tx_cache).await?;

        // Fee estimation and extracting the new cache also stay outside
        // the backend write lock.
        let fees = estimate_tx_fee_per_kb(storage, stable_topoheight, &tx, size, block_version).await?;
        let (balances, multisig) = state.get_sender_cache(tx.get_source())
            .ok_or_else(|| BlockchainError::AccountNotFound(tx.get_source().as_address(mainnet)))?;

        let verified = VerifiedTransaction {
            hash: Arc::clone(&hash),
            tx: Arc::clone(&tx),
            size,
            fees,
            balances,
            multisig,
        };
        let mut backend = self.backend.write().await;
        backend.store_verified(&verification, verified)?;
        backend.get_sorted_tx(&hash).cloned()
    }
}

