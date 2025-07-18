use async_trait::async_trait;
use xelis_common::{
    transaction::verify::ZKPCache,
    crypto::Hash
};

use super::{
    error::BlockchainError,
    mempool::Mempool,
    storage::Storage
};

pub struct TxCache<'a, S: Storage> {
    storage: &'a S,
    mempool: &'a Mempool,
    disabled: bool,
}

impl<'a, S: Storage> TxCache<'a, S> {
    pub fn new(storage: &'a S, mempool: &'a Mempool, disabled: bool) -> Self {
        Self {
            storage,
            mempool,
            disabled
        }
    }
}

#[async_trait]
impl<'a, S: Storage> ZKPCache<BlockchainError> for TxCache<'a, S> {
    async fn is_already_verified(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        if self.disabled {
            Ok(false)
        } else {
            Ok(self.mempool.contains_tx(hash) || self.storage.has_transaction(hash).await?)
        }
    }
}