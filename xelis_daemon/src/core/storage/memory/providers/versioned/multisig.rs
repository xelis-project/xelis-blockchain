use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedMultiSigProvider, MemoryStorage},
};

#[async_trait]
impl VersionedMultiSigProvider for MemoryStorage {
    async fn delete_versioned_multisigs_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| {
                acc.multisig.remove(&topoheight);
            });
        Ok(())
    }

    async fn delete_versioned_multisigs_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| {
                acc.multisig.split_off(&(topoheight + 1));
            });
        Ok(())
    }

    async fn delete_versioned_multisigs_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| Self::delete_versioned_data_below_topoheight(&mut acc.multisig, topoheight, keep_last));

        Ok(())
    }
}
