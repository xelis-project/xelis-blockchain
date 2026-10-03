use async_trait::async_trait;
use xelis_common::{
    transaction::verify::ZKPCache,
    crypto::Hash
};

use super::{
    error::BlockchainError,
    mempool::{Mempool, MempoolBackend},
    storage::Storage
};

pub enum MempoolView<'a> {
    Backend(&'a MempoolBackend),
    Shared(&'a Mempool),
}

impl<'a> From<&'a MempoolBackend> for MempoolView<'a> {
    fn from(mempool: &'a MempoolBackend) -> Self {
        MempoolView::Backend(mempool)
    }
}

impl<'a> From<&'a Mempool> for MempoolView<'a> {
    fn from(mempool: &'a Mempool) -> Self {
        MempoolView::Shared(mempool)
    }
}

pub struct TxCache<'a, S: Storage> {
    storage: &'a S,
    mempool: MempoolView<'a>,
    disabled: bool,
}

impl<'a, S: Storage> TxCache<'a, S> {
    pub fn new(storage: &'a S, mempool: impl Into<MempoolView<'a>>, disabled: bool) -> Self {
        Self {
            storage,
            mempool: mempool.into(),
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
            let contains = match self.mempool {
                MempoolView::Backend(mempool) => mempool.contains_tx(hash),
                MempoolView::Shared(mempool) => mempool.read().await.contains_tx(hash),
            };
            Ok(contains || self.storage.has_transaction(hash).await?)
        }
    }
}