use async_trait::async_trait;
use xelis_common::{
    account::VersionedBalance,
    block::{BlockHeader, TopoHeight},
    crypto::{Hash, PublicKey},
    immutable::Immutable,
};
use crate::core::{
    error::BlockchainError,
    state::FeeProvider,
};
use super::ReferenceProvider;

/// Abstracts the block/DAG lookups required by transaction pre-verification.
#[async_trait]
pub trait TxVerificationProvider: FeeProvider + ReferenceProvider {
    /// Check whether a block with the given hash is stored.
    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    /// Get the height of the block identified by `hash`.
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError>;

    /// Get the block header for the given hash.
    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Immutable<BlockHeader>, BlockchainError>;

    /// Search the highest sender balance that contains an outgoing TX in `[min, max]`.
    async fn get_output_balance_in_range(
        &self,
        key: &PublicKey,
        asset: &Hash,
        min_topoheight: TopoHeight,
        max_topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError>;
}
