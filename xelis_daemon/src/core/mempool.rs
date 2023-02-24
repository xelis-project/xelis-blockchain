use crate::storage::Storage;

use super::error::BlockchainError;
use std::collections::HashMap;
use std::sync::Arc;
use log::warn;
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
    hash: Hash,
    fee: u64,
    size: usize
}

#[derive(serde::Serialize)]
pub struct Mempool {
    txs: HashMap<Hash, Arc<Transaction>>,
    txs_sorted: Vec<SortedTx>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
            txs_sorted: Vec::new()
        }
    }

    // All checks are made in Blockchain before calling this function
    pub fn add_tx(&mut self, hash: Hash, tx: Arc<Transaction>) -> Result<(), BlockchainError> {
        let sorted_tx = SortedTx {
            hash: hash.clone(),
            fee: tx.get_fee(),
            size: tx.size()
        };

        let mut index = 0;
        while index < self.txs_sorted.len() { // TODO Optimize
            if self.txs_sorted[index].fee < sorted_tx.fee {
                break;
            }
            index += 1;
        }

        self.txs_sorted.insert(index, sorted_tx);
        self.txs.insert(hash, tx);
        Ok(())
    }

    pub fn contains_tx(&self, hash: &Hash) -> bool {
        self.txs.contains_key(hash)
    }

    pub fn remove_tx(&mut self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        let tx = self.txs.remove(hash).ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
        let index = self.txs_sorted.iter().position(|tx| tx.hash == *hash).ok_or_else(|| BlockchainError::TxNotFoundInSortedList(hash.clone()))?; // TODO Optimized
        self.txs_sorted.remove(index);

        Ok(tx)
    }

    pub fn get_tx(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        let tx = self.txs.get(hash).ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
        Ok(Arc::clone(tx))
    }

    pub fn view_tx<'a>(&'a self, hash: &Hash) -> Result<&'a Arc<Transaction>, BlockchainError> {
        if let Some(tx) = self.txs.get(hash) {
            return Ok(tx)
        }

        Err(BlockchainError::TxNotFound(hash.clone()))
    }

    pub fn get_sorted_txs(&self) -> &Vec<SortedTx> {
        &self.txs_sorted
    }

    pub fn get_txs(&self) -> &HashMap<Hash, Arc<Transaction>> {
        &self.txs
    }

    pub fn size(&self) -> usize {
        self.txs_sorted.len()
    }

    // delete all old txs not compatible anymore with current state of account
    pub async fn clean_up(&mut self, storage: &Storage, nonces: HashMap<PublicKey, u64>) {
        let txs_sorted = std::mem::replace(&mut self.txs_sorted, vec!());
        for sorted in txs_sorted {
            let tx_nonce;
            let account_nonce;

            if let Some(tx) = self.txs.get(&sorted.hash) {
                tx_nonce = tx.get_nonce();
                account_nonce = if let Some(nonce) = nonces.get(tx.get_owner()) {
                    *nonce
                } else {
                    match storage.get_nonce(tx.get_owner()).await {
                        Ok(nonce) => nonce,
                        Err(e) => {
                            warn!("Error while cleaning up tx {}: {}", sorted.hash, e);
                            // should not be possible, but in case
                            self.txs.remove(&sorted.hash);
                            continue;
                        }
                    }
                };
            } else {
                continue;
            }

            if tx_nonce >= account_nonce {
                self.txs_sorted.push(sorted);
            } else {
                self.txs.remove(&sorted.hash);
            }
        }
    }
}

impl SortedTx {
    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    pub fn get_size(&self) -> usize {
        self.size
    }
}