use std::collections::HashSet;
use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use log::trace;
use xelis_common::{
    crypto::Hash,
    immutable::Immutable,
    serializer::Serializer,
    transaction::Transaction
};
use crate::core::{
    error::{
        BlockchainError,
        DiskContext
    },
    storage::{
        sled::TXS_COUNT,
        ClientProtocolProvider,
        SledStorage,
        TransactionProvider
    }
};

impl SledStorage {
    // Update the txs count and store it on disk
    pub(super) fn store_transactions_count(&mut self, count: u64) -> Result<(), BlockchainError> {
        self.cache_mut().transactions_count = count;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.extra, TXS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }    
}

#[async_trait]
impl TransactionProvider for SledStorage {
    async fn get_transaction(&self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        trace!("get transaction for hash {}", hash);
        self.get_cacheable_arc_data(&self.transactions, self.cache.objects.as_ref().map(|o| &o.transactions_cache), hash, DiskContext::GetTransaction).await
    }

    async fn get_transaction_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        trace!("get transaction size for hash {}", hash);
        self.get_size_from_disk(&self.transactions, hash.as_bytes())
    }

    async fn has_transaction(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has transaction {}", hash);
        self.contains_data_cached(&self.transactions, self.cache.objects.as_ref().map(|o| &o.transactions_cache), hash).await
    }

    // Store a new transaction
    async fn add_transaction(&mut self, hash: &Hash, transaction: &Transaction) -> Result<(), BlockchainError> {
        trace!("add transaction {}", hash);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.transactions, hash, transaction.to_bytes())?;

        Ok(())
    }

    async fn count_transactions(&self) -> Result<u64, BlockchainError> {
        trace!("count transactions");
        Ok(self.cache().transactions_count)
    }

    async fn get_unexecuted_transactions<'a>(&'a self) -> Result<impl Stream<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("get unexecuted transactions");
        Ok(stream::iter(Self::iter_keys::<Hash>(self.snapshot.as_ref(), &self.transactions))
            .map(move |res| async move {
                let tx_hash = res?;
                if !self.is_tx_executed_in_a_block(&tx_hash).await? {
                    return Ok(None);
                }

                Ok(Some(tx_hash))
            })
            .filter_map(|v| async move { v.await.transpose() })
        )
    }

    async fn delete_transaction(&mut self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        Self::delete_cacheable_data::<Hash, HashSet<Hash>>(self.snapshot.as_mut(), &self.tx_blocks, None, hash).await?;
        Self::delete_arc_cacheable_data(self.snapshot.as_mut(), &self.transactions, self.cache.objects.as_mut().map(|o| &mut o.transactions_cache), hash).await
    }
}