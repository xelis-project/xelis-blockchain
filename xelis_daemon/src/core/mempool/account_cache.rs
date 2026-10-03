use std::{collections::HashMap, sync::Arc};
use linked_hash_table::{LinkedHashMap, LinkedHashSet};
use indexmap::IndexSet;
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};
use log::{debug, trace};
use xelis_common::{
    account::Nonce,
    crypto::{elgamal::Ciphertext, Hash},
    transaction::MultiSigPayload,
};
use super::SortedTx;

/// Expected sender state after its pending transaction sequence.
/// Hashes are kept in contiguous nonce order, allowing positions to be inferred
/// from the inclusive nonce bounds. Balances track sender spending changes only;
/// pending receiver credits are not included in this cache.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct AccountCache {
    /// Lowest pending transaction nonce, inclusive.
    pub(super) min: Nonce,
    /// Highest pending transaction nonce, inclusive.
    pub(super) max: Nonce,
    /// Pending transaction hashes in sender nonce order.
    #[schemars(with = "Vec<Arc<Hash>>")]
    pub(super) txs: LinkedHashSet<Arc<Hash>>,
    /// Expected encrypted spending balances after the cached sequence.
    pub(super) balances: HashMap<Hash, Ciphertext>,
    /// Expected multisig configuration after the cached sequence.
    pub(super) multisig: Option<MultiSigPayload>
}

impl AccountCache {
    /// Return the lowest pending nonce, inclusive.
    pub fn get_min(&self) -> Nonce {
        self.min
    }

    /// Return the highest pending nonce, inclusive.
    pub fn get_max(&self) -> Nonce {
        self.max
    }

    /// Return the nonce expected after the last cached transaction.
    pub fn get_next_nonce(&self) -> Nonce {
        self.max + 1
    }

    /// Borrow pending transaction hashes in sender nonce order.
    pub fn get_txs(&self) -> &LinkedHashSet<Arc<Hash>> {
        &self.txs
    }

    /// Update assets loaded by verification, retaining balances of untouched assets.
    pub(super) fn update_balances(&mut self, balances: HashMap<Hash, Ciphertext>) {
        self.balances.extend(balances);
    }

    /// Borrow the expected spending balances used by the next verification.
    pub fn get_balances(&self) -> &HashMap<Hash, Ciphertext> {
        &self.balances
    }

    /// Replace the expected multisig configuration with a verified sender result.
    pub fn set_multisig(&mut self, multisig: Option<MultiSigPayload>) {
        self.multisig = multisig;
    }

    /// Borrow the expected multisig configuration used by the next verification.
    pub fn get_multisig(&self) -> &Option<MultiSigPayload> {
        &self.multisig
    }

    /// Append a transaction hash and expand the inclusive nonce bounds.
    /// The caller must preserve the contiguous sender nonce sequence.
    pub(super) fn update(&mut self, nonce: u64, hash: Arc<Hash>) {
        self.update_nonce_range(nonce);
        self.txs.insert(hash);
    }

    /// Expand the nonce bounds to include the supplied nonce.
    fn update_nonce_range(&mut self, nonce: Nonce) {
        debug_assert!(self.min <= self.max);

        if nonce < self.min {
            self.min = nonce;
        }

        if nonce > self.max {
            self.max = nonce;
        }
    }

    /// Check whether the supplied nonce corresponds to a cached entry.
    /// Relies on transaction hashes being retained in contiguous nonce order.
    pub fn has_tx_with_same_nonce(&self, nonce: Nonce) -> bool {
        if nonce < self.min || nonce > self.max || self.txs.is_empty() {
            return false;
        }

        trace!("has tx with same nonce: {}, max: {}, min: {}, size: {}", nonce, self.max, self.min, self.txs.len());
        let index = ((nonce - self.min) % (self.max + 1 - self.min)) as usize;
        index < self.txs.len()
    }

    /// Infer the hash position for a pending nonce, or return `None` outside the cache.
    /// Relies on the same contiguous nonce ordering as `has_tx_with_same_nonce`.
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

    /// Drop missing transactions and nonces below the current chain nonce.
    /// Record removed hashes for backend deletion and recompute the remaining
    /// bounds. Return `true` when no entries remain; balances are not recomputed.
    pub(super) fn clean_cache(&mut self, txs: &LinkedHashMap<Arc<Hash>, SortedTx>, new_nonce: Nonce, deleted_txs_hashes: &mut IndexSet<Arc<Hash>>) -> bool {
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

