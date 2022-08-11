use crate::crypto::hash::Hash;
use super::serializer::Serializer;
use super::transaction::Transaction;
use super::error::BlockchainError;
use std::collections::HashMap;
use std::sync::Arc;

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
    pub fn add_tx_with_fee(&mut self, hash: Hash, tx: Arc<Transaction>, fee: u64) -> Result<(), BlockchainError> {
        let size = tx.size();
        let sorted_tx = SortedTx {
            hash: hash.clone(),
            fee,
            size: size
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

    pub fn view_tx(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        let tx = self.txs.get(hash).ok_or_else(|| BlockchainError::TxNotFound(hash.clone()))?;
        Ok(Arc::clone(tx))
    }

    pub fn get_sorted_txs(&self) -> &Vec<SortedTx> {
        &self.txs_sorted
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