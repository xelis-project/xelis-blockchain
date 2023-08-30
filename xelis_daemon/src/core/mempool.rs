use super::error::BlockchainError;
use std::cmp::Reverse;
use std::collections::{HashMap, BTreeMap, HashSet};
use std::sync::Arc;
use log::{trace, debug};
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
    size: usize
}

#[derive(serde::Serialize)]
pub struct NonceCache {
    min: u64,
    max: u64,
    // all txs for this user ordered by nonce
    txs: BTreeMap<u64, Arc<Hash>>,
}

#[derive(serde::Serialize)]
pub struct Mempool {
    // store all txs waiting to be included in a block
    txs: HashMap<Arc<Hash>, SortedTx>,
    // store all sender's nonce for faster finding
    nonces_cache: HashMap<PublicKey, NonceCache>,
    // binary tree map for sorted txs hash by fees
    // keys represents fees, while value represents all txs hash
    sorted_txs: BTreeMap<Reverse<u64>, HashSet<Arc<Hash>>>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
            nonces_cache: HashMap::new(),
            sorted_txs: BTreeMap::new()
        }
    }

    // All checks are made in Blockchain before calling this function
    pub fn add_tx(&mut self, hash: Hash, tx: Arc<Transaction>) -> Result<(), BlockchainError> {
        let hash = Arc::new(hash);
        let nonce = tx.get_nonce();
        // update the cache for this owner
        if let Some(cache) = self.nonces_cache.get_mut(tx.get_owner()) {
            // delete the TX if its in the range of already tracked nonces
            trace!("Cache found for owner {} with nonce range {}-{}, nonce = {}", tx.get_owner(), cache.get_min(), cache.get_max(), nonce);
            if nonce >= cache.get_min() && nonce <= cache.get_max() {
                trace!("nonce {} is in range {}-{}", nonce, cache.get_min(), cache.get_max());
                // because it's based on order and we may have the same order
                if let Some(tx_hash) = cache.txs.remove(&nonce) {
                    trace!("TX {} with same nonce found in cache, removing it from sorted txs", tx_hash);
                    // remove the tx hash from sorted txs
                    Self::delete_tx(&mut self.txs, &mut self.sorted_txs, tx_hash);
                }
            }

            cache.update(nonce, hash.clone());
        } else {
            let mut txs = BTreeMap::new();
            txs.insert(nonce, hash.clone());

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
            tx
        };

        let entry = self.sorted_txs.entry(Reverse(sorted_tx.get_fee())).or_insert_with(HashSet::new);
        // add the tx hash in sorted txs
        entry.insert(hash.clone());

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

    pub fn get_sorted_txs(&self) -> &BTreeMap<Reverse<u64>, HashSet<Arc<Hash>>> {
        &self.sorted_txs
    }

    pub fn get_cached_nonce(&self, key: &PublicKey) -> Option<&NonceCache> {
        self.nonces_cache.get(key)
    }

    pub fn size(&self) -> usize {
        self.txs.len()
    }

    pub fn clear(&mut self) {
        self.txs.clear();
        self.sorted_txs.clear();
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
                    cache.txs.retain(|tx_nonce, tx| {
                        let delete = *tx_nonce < nonce;
                        if delete {
                            hashes.push(Arc::clone(tx));
                        }
                        !delete
                    });

                    // delete the nonce cache if no txs are left
                    delete_cache = cache.txs.is_empty();

                    // now delete all necessary txs
                    for hash in hashes {
                        Self::delete_tx(&mut self.txs, &mut self.sorted_txs, hash);
                    }
                }
            }

            if delete_cache {
                trace!("Removing empty nonce cache for owner {}", key);
                self.nonces_cache.remove(&key);
            }
        }
    }


    fn delete_tx(txs: &mut HashMap<Arc<Hash>, SortedTx>, sorted_txs: &mut BTreeMap<Reverse<u64>, HashSet<Arc<Hash>>>, hash: Arc<Hash>) {
        trace!("Trying to delete {}", hash);
        if let Some(sorted_tx) = txs.remove(&hash) {
            trace!("Deleted from HashMap: {}", hash);
            let fee_reverse = Reverse(sorted_tx.get_fee());
            let mut is_empty = false;
            if let Some(hashes) = sorted_txs.get_mut(&fee_reverse) {
                trace!("Removing tx hash {} for fee entry {}", hash, fee_reverse.0);
                hashes.remove(&hash);
                is_empty = hashes.is_empty();
            }

            // don't keep empty data
            if is_empty {
                trace!("Removing empty fee ({}) entry", fee_reverse.0);
                sorted_txs.remove(&fee_reverse);
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

    pub fn get_txs(&self) -> &BTreeMap<u64, Arc<Hash>> {
        &self.txs
    }

    fn update(&mut self, nonce: u64, hash: Arc<Hash>) {
        self.update_nonce_range(nonce);
        self.txs.insert(nonce, hash);
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
        self.txs.get(&nonce)
    }
}