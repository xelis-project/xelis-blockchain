use std::collections::HashMap;
use super::transaction::Transaction;
use super::error::BlockchainError;
use crate::crypto::hash::{Hash, Hashable};

#[derive(serde::Serialize)]
pub struct SortedTx {
    hash: Hash,
    fee: u64,
    size: usize
}

#[derive(serde::Serialize)]
pub struct Mempool {
    txs: HashMap<Hash, Transaction>,
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
    pub fn add_tx(&mut self, hash: Hash, tx: Transaction) -> Result<(), BlockchainError> {
        let size = tx.size();
        let sorted_tx = SortedTx {
            hash: hash.clone(),
            fee: tx.get_fee(),
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

    pub fn remove_tx(&mut self, hash: &Hash) -> Result<Transaction, BlockchainError> {
        match self.txs.remove(hash) {
            Some(v) => {
                match self.txs_sorted.iter().position(|tx| tx.hash == *hash) { // TODO Optimize
                    Some(index) => {
                        self.txs_sorted.remove(index);
                        Ok(v)
                    },
                    None => {
                        panic!("TX is not present in tx sorted!")
                    }
                }
            },
            None => Err(BlockchainError::TxNotFound(hash.clone()))
        }
    }

    pub fn view_tx(&self, hash: &Hash) -> Result<&Transaction, BlockchainError> {
        match self.txs.get(hash) {
            Some(tx) => Ok(tx),
            None => Err(BlockchainError::TxNotFound(hash.clone()))
        }
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