use async_trait::async_trait;

use crate::crypto::Hash;

#[async_trait]
pub trait ZKPCache<E> {
    // Did we already verified the ZK Proofs of this transaction?
    async fn is_already_verified(&self, hash: &Hash) -> Result<bool, E>;
}

#[derive(Default)]
pub struct NoZKPCache;

#[async_trait]
impl<E> ZKPCache<E> for NoZKPCache {
    // Did we already verified the ZK Proofs of this transaction?
    async fn is_already_verified(&self, _: &Hash) -> Result<bool, E> {
        Ok(false)
    }
}