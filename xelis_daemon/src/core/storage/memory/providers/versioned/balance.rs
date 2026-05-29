use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedBalanceProvider, MemoryStorage},
};

#[async_trait]
impl VersionedBalanceProvider for MemoryStorage {
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.iter_mut()
            .map(|(_, acc)| acc.balances.iter_mut())
            .flatten()
            .for_each(|(_, versions)| {
                versions.split_off(&topoheight);
            });

        Ok(())
    }

    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.iter_mut()
            .map(|(_, acc)| acc.balances.iter_mut())
            .flatten()
            .for_each(|(_, versions)| {
                versions.split_off(&(topoheight + 1));
            });

        Ok(())
    }

    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.accounts.iter_mut()
            .map(|(_, acc)| acc.balances.iter_mut())
            .flatten()
            .for_each(|(_, versions)| Self::delete_versioned_data_below_topoheight(versions, topoheight, keep_last));

        Ok(())
    }
}
