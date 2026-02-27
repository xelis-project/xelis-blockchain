use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractEventCallbackProvider, MemoryStorage},
};

#[async_trait]
impl VersionedContractEventCallbackProvider for MemoryStorage {
    async fn delete_versioned_contract_event_callbacks_at_topoheight(&mut self, _: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn delete_versioned_contract_event_callbacks_above_topoheight(&mut self, _: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn delete_versioned_contract_event_callbacks_below_topoheight(&mut self, _: TopoHeight, _: bool) -> Result<(), BlockchainError> {
        Ok(())
    }
}
