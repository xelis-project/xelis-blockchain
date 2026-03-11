use async_trait::async_trait;

use crate::crypto::Hash;

#[async_trait]
pub trait ZKPCache<E> {
    // Did we already verified the ZK Proofs of this transaction?
    async fn is_already_verified(&self, hash: &Hash) -> Result<bool, E>;
}

/// A ZKPCache that always returns false, for use in tests or when we are sure that the proofs are not verified yet
#[derive(Default)]
pub struct NoZKPCache;

#[async_trait]
impl<E> ZKPCache<E> for NoZKPCache {
    // Did we already verified the ZK Proofs of this transaction?
    async fn is_already_verified(&self, _: &Hash) -> Result<bool, E> {
        Ok(false)
    }
}

/// A ZKPCache that always returns true, for use in tests or when we are sure that the proofs are already verified
pub struct TrustedZKPCache;

#[async_trait]
impl<E> ZKPCache<E> for TrustedZKPCache {
    async fn is_already_verified(&self, _: &Hash) -> Result<bool, E> {
        Ok(true)
    }
}