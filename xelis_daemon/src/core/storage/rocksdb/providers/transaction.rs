use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use log::trace;
use xelis_common::{
    crypto::Hash,
    immutable::Immutable,
    transaction::Transaction
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, IteratorMode, TXS_COUNT},
        ClientProtocolProvider,
        RocksStorage,
        TransactionProvider
    }
};

#[async_trait]
impl TransactionProvider for RocksStorage {
    // Get the transaction using its hash
    async fn get_transaction(&self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        trace!("get transaction {}", hash);
        let transaction = self.load_from_disk(Column::Transactions, hash)?;
        Ok(Immutable::Owned(transaction))
    }

    // Get the transaction size using its hash
    async fn get_transaction_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        trace!("get transaction size {}", hash);
        self.get_size_from_disk(Column::Transactions, hash)
    }

    // Count the number of transactions stored
    async fn count_transactions(&self) -> Result<u64, BlockchainError> {
        trace!("count transactions");
        self.load_optional_from_disk(Column::Common, TXS_COUNT)
            .map(|v| v.unwrap_or(0))
    }

    // Get all the unexecuted transactions
    // Those were not executed by the DAG
    async fn get_unexecuted_transactions<'a>(&'a self) -> Result<impl Stream<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("get unexecuted transactions");
        let iter = stream::iter(self.iter_keys(Column::Transactions, IteratorMode::Start)?);
        Ok(
            iter.map(move |res| async move {
                let hash = res?;

                if self.is_tx_executed_in_a_block(&hash).await? {
                    return Ok(None);
                }

                Ok(Some(hash))
            })
            .filter_map(|v| async move { v.await.transpose() })
        )
    }

    // Check if the transaction exists
    async fn has_transaction(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has transaction {}", hash);
        self.contains_data(Column::Transactions, hash)
    }

    // Check if the transaction exists
    async fn add_transaction(&mut self, hash: &Hash, transaction: &Transaction) -> Result<(), BlockchainError> {
        trace!("add transaction {}", hash);
        self.insert_into_disk(Column::Transactions, hash, transaction)
    }

    // Delete a transaction from the storage using its hash
    async fn delete_transaction(&mut self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        trace!("delete transaction {}", hash);
        let transaction = self.get_transaction(hash).await?;
        self.remove_from_disk(Column::Transactions, hash)?;
        Ok(transaction)
    }
}