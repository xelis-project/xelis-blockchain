use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{
        VersionedNonceProvider,
        MemoryStorage,
    },
};

#[async_trait]
impl VersionedNonceProvider for MemoryStorage {
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| {
                acc.nonces.split_off(&topoheight);
            });
        Ok(())
    }

    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| {
                acc.nonces.split_off(&(topoheight + 1));
            });
        Ok(())
    }

    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| Self::delete_versioned_data_below_topoheight(&mut acc.nonces, topoheight, keep_last));

        Ok(())
    }
}
