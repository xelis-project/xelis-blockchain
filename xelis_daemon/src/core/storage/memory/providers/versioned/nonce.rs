use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::VersionedNonceProvider,
};
use super::super::super::MemoryStorage;

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

    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: TopoHeight, _keep_last: bool) -> Result<(), BlockchainError> {
        self.accounts.values_mut()
            .for_each(|acc| {
                let mut to_keep = acc.nonces.split_off(&topoheight);
                to_keep.first_entry()
                    .map(|mut entry| {
                        entry.get_mut()
                            .set_previous_topoheight(None);
                    });

                acc.nonces = to_keep;
            });

        Ok(())
    }
}
