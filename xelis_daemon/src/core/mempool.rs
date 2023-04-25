use super::error::BlockchainError;
use std::cmp::Reverse;
use std::collections::{HashMap, BTreeMap, HashSet};
use std::sync::Arc;
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
    fee: u64,
    size: usize
}

#[derive(serde::Serialize)]
pub struct NonceCache {
    min: u64,
    max: u64,
    txs: HashSet<Arc<Hash>>,
}

#[derive(serde::Serialize)]
pub struct Mempool {
    // store all txs waiting to be included in a block
    txs: HashMap<Arc<Hash>, SortedTx>,
    // store all sender's nonce for faster finding
    nonces: HashMap<PublicKey, NonceCache>,
    // binary tree map for sorted txs hash by fees
    // keys represents fees, while value represents all txs hash
    sorted_txs: BTreeMap<Reverse<u64>, HashSet<Arc<Hash>>>
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
            nonces: HashMap::new(),
            sorted_txs: BTreeMap::new()
        }
    }

    // All checks are made in Blockchain before calling this function
    pub fn add_tx(&mut self, hash: Hash, tx: Arc<Transaction>) -> Result<(), BlockchainError> {
        let hash = Arc::new(hash);
        // update the cache for this owner
        if let Some(cache) = self.nonces.get_mut(tx.get_owner()) {
            cache.update(hash.clone(), tx.get_nonce());
        } else {
            let mut txs = HashSet::new();
            txs.insert(hash.clone());

            let cache = NonceCache {
                max: tx.get_nonce(),
                min: tx.get_nonce(),
                txs
            };
            self.nonces.insert(tx.get_owner().clone(), cache);
        }

        let sorted_tx = SortedTx {
            fee: tx.get_fee(),
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
        self.nonces.get(key)
    }

    pub fn size(&self) -> usize {
        self.txs.len()
    }

    pub fn clear(&mut self) {
        self.txs.clear();
        self.sorted_txs.clear();
        self.nonces.clear();
    }

    // delete all old txs not compatible anymore with current state of account
    pub async fn clean_up(&mut self, nonces: HashMap<PublicKey, u64>) {
        for (key, nonce) in nonces {
            let mut delete_cache = false;
            // check if we have a TX in cache for this owner
            if let Some(cache) = self.nonces.get_mut(&key) {
                // check if the minimum nonce used is lower than new nonce
                if cache.get_min() < nonce {
                    // txs hashes to delete
                    let mut hashes: Vec<Arc<Hash>> = Vec::with_capacity(cache.txs.len());

                    // filter all txs hashes which are not found
                    // or where its nonce is smaller than the new nonce
                    // TODO when drain_filter is stable, use it (allow to get all hashes deleted)
                    cache.txs.retain(|hash| {
                        let delete = {
                            if let Some(sorted_tx) = self.txs.get(hash) {
                                if sorted_tx.get_tx().get_nonce() < nonce {
                                    hashes.push(hash.clone());
                                    true
                                } else {
                                    false
                                }
                            } else {
                                true
                            }
                        };
                        !delete
                    });

                    if cache.txs.is_empty() {
                        delete_cache = true;
                    }

                    // now delete all necessary txs
                    for hash in hashes {
                        if let Some(sorted_tx) = self.txs.remove(&hash) {
                            let fee_reverse = Reverse(sorted_tx.get_fee());
                            let mut is_empty = false;
                            if let Some(hashes) = self.sorted_txs.get_mut(&fee_reverse) {
                                hashes.remove(&hash);
                                is_empty = hashes.is_empty();
                            }

                            // don't keep empty data
                            if is_empty {
                                self.sorted_txs.remove(&fee_reverse);
                            }
                        }
                    }
                }
            }

            if delete_cache {
                self.nonces.remove(&key);
            }
        }
    }
}

impl SortedTx {
    pub fn get_tx(&self) -> &Arc<Transaction> {
        &self.tx
    }

    pub fn get_fee(&self) -> u64 {
        self.fee
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

    pub fn get_txs(&self) -> &HashSet<Arc<Hash>> {
        &self.txs
    }

    fn update(&mut self, hash: Arc<Hash>, nonce: u64) {
        self.add_tx(hash);
        self.set_nonce(nonce);
    }

    fn add_tx(&mut self, hash: Arc<Hash>) {
        self.txs.insert(hash);
    }

    fn set_nonce(&mut self, nonce: u64) {
        debug_assert!(self.min <= self.max);

        if nonce < self.min {
            self.min = nonce;
        }

        if nonce > self.max {
            self.max = nonce;
        }
    }
}