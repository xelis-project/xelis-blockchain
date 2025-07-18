use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

#[async_trait]
pub trait VersionedContractBalanceProvider {
    async fn delete_versioned_contract_balances_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_versioned_contract_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_versioned_contract_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError>;
}