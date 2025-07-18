use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait VersionedRegistrationsProvider {
    // delete versioned registrations at topoheight
    async fn delete_versioned_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // delete versioned registrations above topoheight
    async fn delete_versioned_registrations_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;
}