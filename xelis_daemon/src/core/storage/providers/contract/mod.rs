mod data;
mod contract_logs;
mod balance;
mod scheduled_execution;
mod event_callback;

use std::borrow::Cow;

use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    versioned::Versioned,
    contract::{
        ContractProvider as ContractInfoProvider,
        ContractModule,
    },
};
use crate::core::error::BlockchainError;

pub use data::*;
pub use contract_logs::*;
pub use balance::*;
pub use scheduled_execution::*;
pub use event_callback::*;

// A versioned contract is a contract that can be updated or deleted
pub type VersionedContractModule<'a> = Versioned<Option<Cow<'a, ContractModule>>>;

#[async_trait]
pub trait ContractProvider: ContractDataProvider + ContractLogsProvider + for<'ty> ContractInfoProvider<'ty> + ContractBalanceProvider + ContractScheduledExecutionProvider + ContractEventCallbackProvider {
    // Deploy a contract
    async fn set_last_contract_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: &VersionedContractModule<'a>) -> Result<(), BlockchainError>;

    // Retrieve the last topoheight for a given contract
    async fn get_last_topoheight_for_contract(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError>;

    // Retrieve a contract at a given topoheight
    async fn get_contract_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContractModule<'a>, BlockchainError>;

    // Retrieve a contract at maximum topoheight
    async fn get_contract_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractModule<'a>)>, BlockchainError>;

    // Retrieve all the contracts hashes
    // If minimum_topoheight is provided, it will only return contracts that have a topoheight greater or equal to it
    // If maximum_topoheight is provided, it will only return contracts that have a topoheight less or equal to it
    async fn get_contracts<'a>(&'a self, minimum_topoheight: Option<TopoHeight>, maximum_topoheight: Option<TopoHeight>) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError>;

    // Delete the last topoheight for a given contract
    async fn delete_last_topoheight_for_contract(&mut self, hash: &Hash) -> Result<(), BlockchainError>;

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

    // Add a transaction for a contract
    // this is unrelated to the DAG order, its just for easier lookup of TXs per contract
    async fn add_tx_for_contract(&mut self, contract: &Hash, tx: &Hash) -> Result<(), BlockchainError>;

    // Get all the transactions for a contract
    async fn get_contract_transactions<'a>(&'a self, contract: &Hash) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + Send + Sync + 'a, BlockchainError>;
}