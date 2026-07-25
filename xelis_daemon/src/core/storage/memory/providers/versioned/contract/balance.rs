use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractBalanceProvider, MemoryStorage},
};

#[async_trait]
impl VersionedContractBalanceProvider for MemoryStorage {
    async fn delete_versioned_contract_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.balances.retain(|_, balance_map| {
                    balance_map.split_off(&topoheight);
                    !balance_map.is_empty()
                });
            });
        Ok(())
    }

    async fn delete_versioned_contract_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let topoheight = topoheight.saturating_add(1);
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.balances.retain(|_, balance_map| {
                    balance_map.split_off(&topoheight);
                    !balance_map.is_empty()
                });
            });
        Ok(())
    }

    async fn delete_versioned_contract_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.balances.retain(|_, balance_map| {
                    MemoryStorage::delete_versioned_data_below_topoheight(balance_map, topoheight, keep_last);
                    !balance_map.is_empty()
                });
            });
        Ok(())
    }
}
