use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::VersionedContractProvider,
};
use super::super::super::super::MemoryStorage;

#[async_trait]
impl VersionedContractProvider for MemoryStorage {
    async fn delete_versioned_contracts_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.modules.split_off(&topoheight);
                entry.data.retain(|_, data_map| {
                    data_map.split_off(&topoheight);
                    !data_map.is_empty()
                });
                entry.balances.retain(|_, balance_map| {
                    balance_map.split_off(&topoheight);
                    !balance_map.is_empty()
                });
                entry.events_callbacks.retain(|_, event_map| {
                    event_map.retain(|_, listeners_map| {
                        listeners_map.split_off(&topoheight);
                        !listeners_map.is_empty()
                    });
                    !event_map.is_empty()
                });
            });
        Ok(())
    }

    async fn delete_versioned_contracts_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let topoheight = topoheight + 1;
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.modules.split_off(&topoheight);
                entry.data.retain(|_, data_map| {
                    data_map.split_off(&topoheight);
                    !data_map.is_empty()
                });
                entry.balances.retain(|_, balance_map| {
                    balance_map.split_off(&topoheight);
                    !balance_map.is_empty()
                });
                entry.events_callbacks.retain(|_, event_map| {
                    event_map.retain(|_, listeners_map| {
                        listeners_map.split_off(&topoheight);
                        !listeners_map.is_empty()
                    });
                    !event_map.is_empty()
                });
            });
        Ok(())
    }

    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: TopoHeight, _keep_last: bool) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                // TODO: if keep_last, we must check that the last value is not deleted, even if its below the topoheight.
                let mut to_keep = entry.modules.split_off(&topoheight);
                    to_keep.first_entry()
                        .map(|mut entry| {
                            entry.get_mut().set_previous_topoheight(None);
                        });

                entry.modules = to_keep;
                entry.data.retain(|_, data_map| {
                    let to_keep = data_map.split_off(&topoheight);
                    *data_map = to_keep;

                    !data_map.is_empty()
                });
                entry.balances.retain(|_, balance_map| {
                    let to_keep = balance_map.split_off(&topoheight);
                    *balance_map = to_keep;

                    !balance_map.is_empty()
                });

                entry.events_callbacks.retain(|_, event_map| {
                    event_map.retain(|_, listeners_map| {
                        let to_keep = listeners_map.split_off(&topoheight);
                        *listeners_map = to_keep;

                        !listeners_map.is_empty()
                    });
                    !event_map.is_empty()
                });
            });

        Ok(())
    }
}
