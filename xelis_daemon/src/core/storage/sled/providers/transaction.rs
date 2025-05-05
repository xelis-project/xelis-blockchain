use std::{collections::HashSet, sync::Arc};
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
        SledStorage,
        TransactionProvider
    }
};

impl SledStorage {
    // Update the txs count and store it on disk
    pub(super) fn store_transactions_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.cache.transactions_count = count;
        } else {
            self.cache.transactions_count = count;
        }
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, TXS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }    
}

#[async_trait]
impl TransactionProvider for SledStorage {
    async fn get_transaction(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        trace!("get transaction for hash {}", hash);
        self.get_cacheable_arc_data(&self.transactions, &self.transactions_cache, hash, DiskContext::GetTransaction).await
    }

    async fn get_transaction_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        trace!("get transaction size for hash {}", hash);
        self.get_size_from_disk(&self.transactions, hash.as_bytes())
    }

    async fn has_transaction(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has transaction {}", hash);
        self.contains_data_cached(&self.transactions, &self.transactions_cache, hash).await
    }

    async fn count_transactions(&self) -> Result<u64, BlockchainError> {
        trace!("count transactions");
        let count = if let Some(snapshot) = self.snapshot.as_ref() {
            snapshot.cache.transactions_count
        } else {
            self.cache.transactions_count
        };
        Ok(count)
    }

    async fn delete_transaction(&mut self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        Self::delete_cacheable_data::<Hash, HashSet<Hash>>(self.snapshot.as_mut(), &self.tx_blocks, None, hash).await?;
        Self::delete_arc_cacheable_data(self.snapshot.as_mut(), &self.transactions, self.cache.transactions_cache.as_mut(), hash).await
    }
}