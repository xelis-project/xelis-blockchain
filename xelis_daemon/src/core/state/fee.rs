use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
};

use crate::core::{error::BlockchainError, storage::Storage};

/// Abstracts the lookups performed by fee estimation logic.
#[async_trait]
pub trait FeeProvider: Send + Sync {
    /// Is the account considered registered at the given topoheight?
    /// This is used to determine whether a transfer to this account would require an extra fee for account registration.
    async fn is_account_registered(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError>;
    
    /// Whether the provider is operating in a mainnet context (affects address formatting).
    fn is_mainnet(&self) -> bool;
}

#[async_trait]
impl<S: Storage> FeeProvider for S {
    async fn is_account_registered(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        self.is_account_registered_for_topoheight(key, topoheight).await
    }

    fn is_mainnet(&self) -> bool {
        S::is_mainnet(self)
    }
}