use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractEventCallbackProvider, MemoryStorage},
};

#[async_trait]
impl VersionedContractEventCallbackProvider for MemoryStorage {
    async fn delete_versioned_contract_event_callbacks_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.state.contracts.iter_mut()
            .for_each(|(_, entry)| {
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

    async fn delete_versioned_contract_event_callbacks_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.state.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.events_callbacks.retain(|_, event_map| {
                    event_map.retain(|_, listeners_map| {
                        listeners_map.split_off(&topoheight.saturating_add(1));
                        !listeners_map.is_empty()
                    });
                    !event_map.is_empty()
                });
            });
        Ok(())
    }

    async fn delete_versioned_contract_event_callbacks_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        self.state.contracts.iter_mut()
            .for_each(|(_, entry)| {
                entry.events_callbacks.retain(|_, event_map| {
                    event_map.retain(|_, listeners_map| {
                        MemoryStorage::delete_versioned_data_below_topoheight(listeners_map, topoheight, keep_last);
                        !listeners_map.is_empty()
                    });
                    !event_map.is_empty()
                });
            });
        Ok(())
    }
}
