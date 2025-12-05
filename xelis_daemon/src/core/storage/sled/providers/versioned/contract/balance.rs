use async_trait::async_trait;
use log::trace;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        SledStorage,
        VersionedContractBalanceProvider
    }
};

#[async_trait]
impl VersionedContractBalanceProvider for SledStorage {
    async fn delete_versioned_contract_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts balances at topoheight {}", topoheight);
        Self::delete_versioned_tree_at_topoheight(&mut self.snapshot, &self.contracts_balances, &self.versioned_contracts_balances, topoheight)
    }

    async fn delete_versioned_contract_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts balances above topoheight {}", topoheight);
        Self::delete_versioned_tree_above_topoheight(&mut self.snapshot, &self.contracts_balances, &self.versioned_contracts_balances, topoheight, DiskContext::ContractBalance)
    }

    async fn delete_versioned_contract_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        trace!("delete versioned contracts balances below topoheight {}", topoheight);
        Self::delete_versioned_tree_below_topoheight(&mut self.snapshot, &self.contracts_balances, &self.versioned_contracts_balances, topoheight, keep_last, DiskContext::ContractBalance)
    }
}