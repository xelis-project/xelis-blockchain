use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractBalanceProvider, MemoryStorage},
};

#[async_trait]
impl VersionedContractBalanceProvider for MemoryStorage {
    async fn delete_versioned_contract_balances_at_topoheight(&mut self, _: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn delete_versioned_contract_balances_above_topoheight(&mut self, _: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn delete_versioned_contract_balances_below_topoheight(&mut self, _: TopoHeight, _: bool) -> Result<(), BlockchainError> {
        Ok(())
    }
}
