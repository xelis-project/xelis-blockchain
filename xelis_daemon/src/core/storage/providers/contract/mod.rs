mod data;
mod contract_logs;
mod balance;
mod delayed_execution;

use std::borrow::Cow;

use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    versioned_type::Versioned,
    contract::ContractProvider as ContractInfoProvider,
};
use xelis_vm::Module;
use crate::core::error::BlockchainError;

pub use data::*;
pub use contract_logs::*;
pub use balance::*;
pub use delayed_execution::*;

// A versioned contract is a contract that can be updated or deleted
pub type VersionedContract<'a> = Versioned<Option<Cow<'a, Module>>>;

#[async_trait]
pub trait ContractProvider: ContractDataProvider + ContractLogsProvider + ContractInfoProvider + ContractBalanceProvider + ContractDelayedExecutionProvider {
    // Deploy a contract
    async fn set_last_contract_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: &VersionedContract<'a>) -> Result<(), BlockchainError>;

    // Retrieve the last topoheight for a given contract
    async fn get_last_topoheight_for_contract(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError>;

    // Retrieve a contract at a given topoheight
    async fn get_contract_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContract<'a>, BlockchainError>;

    // Retrieve a contract at maximum topoheight
    async fn get_contract_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContract<'a>)>, BlockchainError>;

    // Retrieve all the contracts hashes
    async fn get_contracts<'a>(&'a self, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError>;

    // Delete the last topoheight for a given contract
    async fn delete_last_topoheight_for_contract(&mut self, hash: &Hash) -> Result<(), BlockchainError>;

    // Check if a contract exists
    // and that it has a Module
    async fn has_contract(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Check if we have the contract
    async fn has_contract_pointer(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Check if a contract exists at a given topoheight
    // If the version is None, it returns None
    async fn has_contract_module_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Check if a contract version exists at a given topoheight
    async fn has_contract_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Check if a contract version exists at a maximum given topoheight
    // This must returns false if there is no module available as latest version
    async fn has_contract_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Count the number of contracts
    async fn count_contracts(&self) -> Result<u64, BlockchainError>;
}