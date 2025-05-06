use async_trait::async_trait;
use xelis_common::{
    crypto::Hash,
    immutable::Immutable,
    transaction::Transaction
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::Column,
        RocksStorage,
        TransactionProvider
    }
};

#[async_trait]
impl TransactionProvider for RocksStorage {
    // Get the transaction using its hash
    async fn get_transaction(&self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        let transaction = self.load_from_disk(Column::Transactions, hash)?;
        Ok(Immutable::Owned(transaction))
    }

    // Get the transaction size using its hash
    async fn get_transaction_size(&self, hash: &Hash) -> Result<usize, BlockchainError> {
        self.get_size_from_disk(Column::Transactions, hash)
    }

    // Count the number of transactions stored
    async fn count_transactions(&self) -> Result<u64, BlockchainError> {
        // TODO: to implement with cache
        Ok(0)
    }

    // Check if the transaction exists
    async fn has_transaction(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.contains_data(Column::Transactions, hash)
    }

    // Check if the transaction exists
    async fn add_transaction(&mut self, hash: &Hash, transaction: &Transaction) -> Result<(), BlockchainError> {
        self.insert_into_disk(Column::Transactions, hash, transaction)
    }

    // Delete a transaction from the storage using its hash
    async fn delete_transaction(&mut self, hash: &Hash) -> Result<Immutable<Transaction>, BlockchainError> {
        let transaction = self.get_transaction(hash).await?;
        self.remove_from_disk(Column::Transactions, hash)?;
        Ok(transaction)
    }
}