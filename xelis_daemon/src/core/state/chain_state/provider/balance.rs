use async_trait::async_trait;
use xelis_common::{
    account::VersionedBalance,
    block::TopoHeight,
    crypto::{Hash, PublicKey},
};
use crate::core::error::BlockchainError;

/// Abstracts the balance lookups needed to resolve a versioned balance
/// against a transaction reference.
#[async_trait]
pub trait BalanceSelectorProvider: Send + Sync {
    /// Whether this node is running on mainnet.
    fn is_mainnet(&self) -> bool;

    /// Search the highest sender balance containing an outgoing TX in `[min, max]`.
    async fn get_output_balance_in_range(
        &self,
        key: &PublicKey,
        asset: &Hash,
        min_topoheight: TopoHeight,
        max_topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError>;

    /// Get the balance at or below the requested topoheight for asset and key.
    async fn get_balance_at_maximum_topoheight(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError>;

    /// Get a new versioned balance based on the requested topoheight.
    /// Returns `(balance, is_new)` where `is_new` is true if no previous balance was found.
    async fn get_new_versioned_balance(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<(VersionedBalance, bool), BlockchainError>;
}
