use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait VersionedNonceProvider {
    // delete versioned nonces at topoheight
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned nonces above topoheight
    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned nonces below topoheight
    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError>;
}