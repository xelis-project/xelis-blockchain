use std::ops::Bound::{Excluded, Unbounded};
use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{memory::ContractEntry, VersionedScheduledExecutionsProvider, MemoryStorage},
};

#[async_trait]
impl VersionedScheduledExecutionsProvider for MemoryStorage {
    async fn delete_scheduled_executions_at_registration_topoheight(&mut self, registration_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let state = &mut self.state;
        for (contract, entry) in state.contracts.iter_mut() {
            // Only this contract's version at the requested registration topoheight is removed.
            if let Some(version) = entry.scheduled_executions.remove(&registration_topoheight) {
                // Rollback removes registrations newest first, so rewind the latest pointer directly.
                entry.scheduled_execution_pointer = version.get_previous_topoheight();
                if let Some(target) = version.get().kind.execution_topoheight() {
                    if let Some(items) = state.scheduled_executions_per_topoheight.get_mut(&target) {
                        items.remove(contract);
                        if items.is_empty() {
                            state.scheduled_executions_per_topoheight.remove(&target);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn delete_scheduled_executions_above_registration_topoheight(&mut self, registration_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let state = &mut self.state;
        for (contract, entry) in state.contracts.iter_mut() {
            // Remove newest registrations first, rewinding the latest pointer as each row is removed.
            while let Some(last) = entry.scheduled_executions.last_entry() {
                if *last.key() <= registration_topoheight {
                    break;
                }
                let (registration, version) = last.remove_entry();
                entry.unlink_scheduled_execution_registration(registration, version.get_previous_topoheight());
                if let Some(target) = version.get().kind.execution_topoheight() {
                    if let Some(items) = state.scheduled_executions_per_topoheight.get_mut(&target) {
                        items.remove(contract);
                        if items.is_empty() {
                            state.scheduled_executions_per_topoheight.remove(&target);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn delete_scheduled_executions_below_topoheight(&mut self, execution_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let state = &mut self.state;
        // Consume existing index buckets in execution order without collecting their entries.
        while let Some(first) = state.scheduled_executions_per_topoheight.first_entry() {
            if *first.key() >= execution_topoheight {
                break;
            }
            let (_, executions) = first.remove_entry();
            for (contract, registration) in executions {
                let entry = state.contracts.get_mut(&contract)
                    .ok_or(BlockchainError::CorruptedData)?;

                let version = entry.scheduled_executions.remove(&registration)
                    .ok_or(BlockchainError::CorruptedData)?;

                entry.unlink_scheduled_execution_registration(registration, version.get_previous_topoheight());
            }
        }
        Ok(())
    }
}

impl ContractEntry {
    // The versions are ordered by registration topoheight, so the immediate successor can be
    // found directly. This also handles pruning an interior version of the history.
    fn unlink_scheduled_execution_registration(&mut self, registration: TopoHeight, previous: Option<TopoHeight>) {
        if self.scheduled_execution_pointer == Some(registration) {
            self.scheduled_execution_pointer = previous;
        } else if let Some((_, successor)) = self.scheduled_executions.range_mut((Excluded(registration), Unbounded)).next() {
            successor.set_previous_topoheight(previous);
        }
    }
}
