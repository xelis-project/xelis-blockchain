use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage
};

#[async_trait]
pub trait VersionedNonceProvider {
    // delete versioned nonces at topoheight
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned nonces above topoheight
    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned nonces below topoheight
    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedNonceProvider for SledStorage {
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces at topoheight {}", topoheight);
        Self::delete_versioned_tree_at_topoheight(&mut self.snapshot, &self.nonces, &self.versioned_nonces, topoheight)
    }

    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces above topoheight {}!", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.versioned_nonces, topoheight)
    }

    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: u64, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces below topoheight {}!", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.nonces, &self.versioned_nonces, topoheight, keep_last, DiskContext::VersionedNonce)
    }
}