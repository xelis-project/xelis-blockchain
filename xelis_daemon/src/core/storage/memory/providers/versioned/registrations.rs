use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::VersionedRegistrationsProvider,
};
use super::super::super::MemoryStorage;

#[async_trait]
impl VersionedRegistrationsProvider for MemoryStorage {
    async fn delete_versioned_registrations_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.iter_mut()
            .map(|(_, acc)| &mut acc.registered_at)
            .for_each(|registered_at| {
                if registered_at.is_some_and(|t| t == topoheight) {
                    *registered_at = None;
                }
            });
        Ok(())
    }

    async fn delete_versioned_registrations_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.iter_mut()
            .map(|(_, acc)| &mut acc.registered_at)
            .for_each(|registered_at| {
                if registered_at.is_some_and(|t| t > topoheight) {
                    *registered_at = None;
                }
            });
        Ok(())
    }
}
