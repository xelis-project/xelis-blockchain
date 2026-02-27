use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::VersionedMultiSigProvider,
};
use super::super::super::MemoryStorage;

#[async_trait]
impl VersionedMultiSigProvider for MemoryStorage {
    async fn delete_versioned_multisigs_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| {
                acc.multisig.split_off(&topoheight);
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

    async fn delete_versioned_multisigs_below_topoheight(&mut self, topoheight: TopoHeight, _keep_last: bool) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| {
                let mut to_keep = acc.multisig.split_off(&topoheight);
                to_keep.first_entry()
                    .map(|mut entry| {
                        entry.get_mut()
                            .set_previous_topoheight(None);
                    });

                acc.multisig = to_keep;
            });

        Ok(())
    }
}
