use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash
};
use crate::core::{
    error::BlockchainError,
    storage::{
        ContractBalanceProvider,
        RocksStorage,
        VersionedContractBalance
    }
};

#[async_trait]
impl ContractBalanceProvider for RocksStorage {
    // Check if a balance exists for asset and contract
    async fn has_contract_balance_for(&self, contract: &Hash, asset: &Hash) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if a balance exists for asset and contract at specific topoheight
    async fn has_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Get the balance at a specific topoheight for asset and contract
    async fn get_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedContractBalance, BlockchainError> {
        todo!()
    }

    // Get the balance under or equal topoheight requested for asset and contract
    async fn get_contract_balance_at_maximum_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError> {
        todo!()
    }

    // Get the last topoheight that the contract has a balance
    async fn get_last_topoheight_for_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        todo!()
    }

    // Get the latest topoheight & versioned data for a contract balance
    async fn get_last_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<(TopoHeight, VersionedContractBalance), BlockchainError> {
        todo!()
    }

    // Get all the contract balances assets
    async fn get_contract_assets_for(&self, contract: &Hash) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>>, BlockchainError> {
        Ok(std::iter::empty())
    }

    // Set the last topoheight that the contract has a balance
    async fn set_last_topoheight_for_contract_balance(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // Set the last balance for asset and contract at specific topoheight
    async fn set_last_contract_balance_to(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight, balance: VersionedContractBalance) -> Result<(), BlockchainError> {
        todo!()
    }
}