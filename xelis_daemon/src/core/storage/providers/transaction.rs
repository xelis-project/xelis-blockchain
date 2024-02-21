use std::{collections::HashSet, sync::{atomic::Ordering, Arc}};
use async_trait::async_trait;
use log::trace;
use xelis_common::{
    transaction::Transaction,
    crypto::Hash,
};
use crate::core::{
    error::{
        BlockchainError,
        DiskContext
    },
    storage::{
        sled::TXS_COUNT,
        SledStorage
    }
};

#[async_trait]
pub trait TransactionProvider {
    // Get the transaction using its hash
    async fn get_transaction(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError>;

    // Get the transaction size using its hash
    async fn get_transaction_size(&self, hash: &Hash) -> Result<usize, BlockchainError>;

    // Count the number of transactions stored
    async fn count_transactions(&self) -> Result<u64, BlockchainError>;

    // Check if the transaction exists
    async fn has_transaction(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Delete a transaction from the storage using its hash
    async fn delete_transaction(&mut self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError>;
}

impl SledStorage {
    // Update the txs count and store it on disk
    pub(super) fn store_transactions_count(&self, count: u64) -> Result<(), BlockchainError> {
        self.transactions_count.store(count, Ordering::SeqCst);
        self.extra.insert(TXS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }    
}

#[async_trait]
impl TransactionProvider for SledStorage {
    async fn get_transaction(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        trace!("get transaction for hash {}", hash);
        self.get_cacheable_arc_data(&self.transactions, &self.transactions_cache, hash).await
    }

    async fn get_transaction_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        trace!("get transaction size for hash {}", hash);
        let data = self.transactions.get(hash.as_bytes())?;
        data.map(|data| data.len()).ok_or(BlockchainError::NotFoundOnDisk(DiskContext::LoadData))
    }

    async fn has_transaction(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has transaction {}", hash);
        self.contains_data(&self.transactions, &self.transactions_cache, hash).await
    }

    async fn count_transactions(&self) -> Result<u64, BlockchainError> {
        trace!("count transactions");
        Ok(self.transactions_count.load(Ordering::SeqCst))
    }

    async fn delete_transaction(&mut self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        self.delete_cacheable_data::<Hash, HashSet<Hash>>(&self.tx_blocks, &None, hash).await?;
        self.delete_data(&self.transactions, &self.transactions_cache, hash).await
    }
}