use async_trait::async_trait;
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
    async fn set_last_contract_data_to<'a>(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight, contract: VersionedContractData) -> Result<(), BlockchainError>;

    // Set the last topoheight for a given contract data
    async fn set_last_topoheight_for_contract_data(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Retrieve the last topoheight for a given contract data
    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &ValueCell) -> Result<TopoHeight, BlockchainError>;

    // Retrieve a contract data at a given topoheight
    async fn get_contract_data_at_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError>;

    // Retrieve a contract data at maximum topoheight
    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError>;

    // Retrieve the topoheight of a contract data at maximum topoheight
    async fn get_contract_data_topoheight_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError>;

    // Store a contract data at a given topoheight
    async fn set_contract_data_at_topoheight<'a>(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight, data: VersionedContractData) -> Result<(), BlockchainError>;

    // Check if a contract data exists at a given topoheight
    // If the version is None, it returns None
    async fn has_contract_data_at_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Check if we have a contract data version at a given topoheight
    // It only checks if the topoheight exists
    async fn has_contract_data_at_exact_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Check if we have a contract data pointer
    async fn has_contract_data_pointer(&self, contract: &Hash, key: &ValueCell) -> Result<bool, BlockchainError>;

    // Delete the last topoheight for a given contract data
    async fn delete_last_topoheight_for_contract_data(&mut self, contract: &Hash, key: &ValueCell) -> Result<(), BlockchainError>;
}