use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash
};
use crate::core::{error::BlockchainError, storage::{ContractProvider, RocksStorage, VersionedContract}};

#[async_trait]
impl ContractProvider for RocksStorage {
    // Deploy a contract
    async fn set_last_contract_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContract<'a>) -> Result<(), BlockchainError> {
        todo!()
    }

    // Set the last topoheight for a given contract
    async fn set_last_topoheight_for_contract(&mut self, hash: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // Retrieve the last topoheight for a given contract
    async fn get_last_topoheight_for_contract(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        todo!()
    }

    // Retrieve a contract at a given topoheight
    async fn get_contract_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContract<'a>, BlockchainError> {
        todo!()
    }

    // Retrieve a contract at maximum topoheight
    async fn get_contract_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContract<'a>)>, BlockchainError> {
        todo!()
    }

    // Retrieve all the contracts hashes
    async fn get_contracts(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexSet<Hash>, BlockchainError> {
        todo!()
    }

    // Retrieve the size of a contract at a given topoheight without loading the contract
    async fn get_contract_size_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<usize, BlockchainError> {
        todo!()
    }

    // Store a contract at a given topoheight
    async fn set_contract_at_topoheight<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: VersionedContract<'a>) -> Result<(), BlockchainError> {
        todo!()
    }

    // Delete the last topoheight for a given contract
    async fn delete_last_topoheight_for_contract(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        todo!()
    }

    // Check if a contract exists
    // and that it has a Module
    async fn has_contract(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if we have the contract
    async fn has_contract_pointer(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if a contract exists at a given topoheight
    // If the version is None, it returns None
    async fn has_contract_module_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if a contract version exists at a given topoheight
    async fn has_contract_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Check if a contract version exists at a maximum given topoheight
    async fn has_contract_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Count the number of contracts
    async fn count_contracts(&self) -> Result<u64, BlockchainError> {
        todo!()
    }
}