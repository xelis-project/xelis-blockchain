use async_trait::async_trait;
use xelis_vm::ValueCell;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::{error::BlockchainError, storage::{ContractDataProvider, RocksStorage, VersionedContractData}};

#[async_trait]
impl ContractDataProvider for RocksStorage {
    // Set a contract data
    async fn set_last_contract_data_to<'a>(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight, version: VersionedContractData) -> Result<(), BlockchainError> {
        todo!()
    }

    // Set the last topoheight for a given contract data
    async fn set_last_topoheight_for_contract_data(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // Retrieve the last topoheight for a given contract data
    async fn get_last_topoheight_for_contract_data(&self, contract: &Hash, key: &ValueCell) -> Result<TopoHeight, BlockchainError> {
        todo!()
    }

    // Retrieve a contract data at a given topoheight
    async fn get_contract_data_at_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<VersionedContractData, BlockchainError> {
        todo!()
    }

    // Retrieve a contract data at maximum topoheight
    async fn get_contract_data_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractData)>, BlockchainError> {
        todo!()
    }

    // Retrieve the topoheight of a contract data at maximum topoheight
    async fn get_contract_data_topoheight_at_maximum_topoheight_for<'a>(&self, contract: &Hash, key: &ValueCell, maximum_topoheight: TopoHeight) -> Result<Option<TopoHeight>, BlockchainError> {
        todo!()
    }

    // Store a contract data at a given topoheight
    async fn set_contract_data_at_topoheight<'a>(&mut self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight, data: VersionedContractData) -> Result<(), BlockchainError> {
        todo!()
    }

    // Check if a contract data exists at a given topoheight
    // If the version is None, it returns None
    async fn has_contract_data_at_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if we have a contract data version at a given topoheight
    // It only checks if the topoheight exists
    async fn has_contract_data_at_exact_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if we have a contract data pointer
    async fn has_contract_data_pointer(&self, contract: &Hash, key: &ValueCell) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Delete the last topoheight for a given contract data
    async fn delete_last_topoheight_for_contract_data(&mut self, contract: &Hash, key: &ValueCell) -> Result<(), BlockchainError> {
        todo!()
    }
}