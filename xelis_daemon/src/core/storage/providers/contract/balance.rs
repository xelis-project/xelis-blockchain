use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    versioned_type::Versioned
};
use crate::core::error::BlockchainError;

pub type VersionedContractBalance = Versioned<u64>;

#[async_trait]
pub trait ContractBalanceProvider {
    // Check if a balance exists for asset and contract
    async fn has_contract_balance_for(&self, contract: &Hash, asset: &Hash) -> Result<bool, BlockchainError>;

    // Check if a balance exists for asset and contract at specific topoheight
    async fn has_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the balance at a specific topoheight for asset and contract
    async fn get_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedContractBalance, BlockchainError>;

    // Get the balance under or equal topoheight requested for asset and contract
    async fn get_contract_balance_at_maximum_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError>;

    // Get the last topoheight that the contract has a balance
    async fn get_last_topoheight_for_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<Option<TopoHeight>, BlockchainError>;

    // Get the latest topoheight & versioned data for a contract balance
    async fn get_last_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<(TopoHeight, VersionedContractBalance), BlockchainError>;

    // Get all the contract balances assets
    async fn get_contract_assets_for(&self, contract: &Hash) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>>, BlockchainError>;

    // Set the last topoheight that the contract has a balance
    async fn set_last_topoheight_for_contract_balance(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Set the last balance for asset and contract at specific topoheight
    async fn set_last_contract_balance_to(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight, balance: VersionedContractBalance) -> Result<(), BlockchainError>;
}