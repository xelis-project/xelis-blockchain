use async_trait::async_trait;
use futures::Stream;
use xelis_vm::ValueCell;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    versioned_type::Versioned,
};
use crate::core::error::BlockchainError;

// Versioned contract data
// ValueCell is optional because it can be deleted
pub type VersionedContractData = Versioned<Option<ValueCell>>;

#[async_trait]
pub trait ContractDataProvider {
    // Set a contract data
    async fn set_last_contract_data_to(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight, version: &VersionedContractData) -> Result<(), BlockchainError>;

    // Retrieve the last topoheight for a given contract data
    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &ValueCell) -> Result<Option<TopoHeight>, BlockchainError>;

    // Retrieve a contract data at a given topoheight
    async fn get_contract_data_at_exact_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError>;

    // Retrieve a contract data at maximum topoheight
    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError>;

    // Retrieve the topoheight of a contract data at maximum topoheight
    async fn get_contract_data_topoheight_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError>;

    // Check if a contract data exists at a given topoheight
    // If the version is None, it returns false
    async fn has_contract_data_at_maximum_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Check if we have a contract data version at a given topoheight
    // It only checks if the topoheight exists
    async fn has_contract_data_at_exact_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get all the contract data entries at a maximum topoheight
    async fn get_contract_data_entries_at_maximum_topoheight<'a>(&'a self, contract: &'a Hash, topoheight: TopoHeight) -> Result<impl Stream<Item = Result<(ValueCell, ValueCell), BlockchainError>> + Send + 'a, BlockchainError>;
}