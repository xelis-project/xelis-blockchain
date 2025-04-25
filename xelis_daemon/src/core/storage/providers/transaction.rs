use std::sync::Arc;
use async_trait::async_trait;
use xelis_common::{
    transaction::Transaction,
    crypto::Hash,
};
use crate::core::error::BlockchainError;

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