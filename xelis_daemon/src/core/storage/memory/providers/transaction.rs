use pooled_arc::PooledArc;
use std::sync::Arc;
use async_trait::async_trait;
use futures::stream;
use anyhow::Context;
use xelis_common::{
    crypto::Hash,
    immutable::Immutable,
    serializer::Serializer,
    transaction::Transaction,
};
use futures::Stream;
use crate::core::{
    error::BlockchainError,
    storage::{TransactionProvider, memory::TransactionEntry},
};
use super::super::MemoryStorage;

#[async_trait]
impl TransactionProvider for MemoryStorage {
    async fn get_transaction(&self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        self.transactions.get(hash)
            .map(|entry| Immutable::Arc(entry.transaction.clone()))
            .with_context(|| format!("Transaction not found: {}", hash))
            .map_err(|e| e.into())
    }

    async fn get_transaction_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        self.transactions.get(hash)
            .map(|entry| entry.transaction.size())
            .with_context(|| format!("Transaction size not found for hash: {}", hash))
            .map_err(|e| e.into())
    }

    async fn count_transactions(&self) -> Result<u64, BlockchainError> {
        Ok(self.transactions.len() as u64)
    }

    async fn get_unexecuted_transactions<'a>(&'a self) -> Result<impl Stream<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        let iter = self.transactions.iter()
            .filter_map(|(hash, entry)| {
                if entry.executed_in_block.is_none() {
                    Some(Ok(hash.as_ref().clone()))
                } else {
                    None
                }
            });
        Ok(stream::iter(iter))
    }

    async fn has_transaction(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.transactions.contains_key(hash))
    }

    async fn add_transaction(&mut self, hash: &Hash, transaction: &Transaction) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(hash);
        self.transactions.insert(shared, TransactionEntry {
            transaction: Arc::new(transaction.clone()),
            executed_in_block: None,
            linked_blocks: Default::default(),
        });
        Ok(())
    }

    async fn delete_transaction(&mut self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        let entry = self.transactions.remove(hash)
            .with_context(|| format!("Cannot delete transaction, not found: {}", hash))?;

        if let Some(contract) = entry.transaction.invoked_contract().and_then(|contract| self.contracts.get_mut(contract)) {
            contract.transactions.remove(hash);
        }

        Ok(Immutable::Arc(entry.transaction))
    }
}
