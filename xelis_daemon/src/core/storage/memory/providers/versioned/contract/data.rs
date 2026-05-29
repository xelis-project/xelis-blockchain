use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractDataProvider, MemoryStorage},
};

#[async_trait]
impl VersionedContractDataProvider for MemoryStorage {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, _: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn delete_versioned_contract_data_above_topoheight(&mut self, _: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn delete_versioned_contract_data_below_topoheight(&mut self, _: TopoHeight, _: bool) -> Result<(), BlockchainError> {
        Ok(())
    }
}
