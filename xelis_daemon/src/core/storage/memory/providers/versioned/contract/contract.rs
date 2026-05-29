use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractProvider, MemoryStorage},
};

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

    async fn delete_versioned_contracts_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(_, entry)| {
                Self::delete_versioned_data_below_topoheight(&mut entry.modules, topoheight, keep_last);
                entry.data.retain(|_, data_map| {
                    Self::delete_versioned_data_below_topoheight(data_map, topoheight, keep_last);

                    !data_map.is_empty()
                });
                entry.balances.retain(|_, balance_map| {
                    Self::delete_versioned_data_below_topoheight(balance_map, topoheight, keep_last);
                    !balance_map.is_empty()
                });

                entry.events_callbacks.retain(|_, event_map| {
                    event_map.retain(|_, listeners_map| {
                        Self::delete_versioned_data_below_topoheight(listeners_map, topoheight, keep_last);

                        !listeners_map.is_empty()
                    });
                    !event_map.is_empty()
                });
            });

        Ok(())
    }
}
