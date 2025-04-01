use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage
};

#[async_trait]
pub trait VersionedContractDataProvider {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError>;
}

#[async_trait]
impl VersionedContractDataProvider for SledStorage {
    async fn delete_versioned_contract_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts data at topoheight {}", topoheight);
        Self::delete_versioned_tree_at_topoheight(&mut self.snapshot, &self.contracts_data, &self.versioned_contracts_data, topoheight)
    }

    async fn delete_versioned_contract_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts data above topoheight {}", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.versioned_contracts_data, topoheight)
    }

    async fn delete_versioned_contract_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts data below topoheight {}", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.contracts_data, &self.versioned_contracts_data, topoheight, keep_last, DiskContext::VersionedContractData)
    }
}