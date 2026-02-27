use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedScheduledExecutionsProvider, MemoryStorage},
};

#[async_trait]
impl VersionedScheduledExecutionsProvider for MemoryStorage {
    async fn delete_scheduled_executions_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(contract, contract_data)| {
                contract_data.scheduled_executions.split_off(&topoheight)
                .into_iter()
                .flat_map(|(_, entries)| entries.into_keys())
                .for_each(|exec_topo| {
                    let is_empty = self.scheduled_executions_per_topoheight.get_mut(&exec_topo)
                        .map_or(false, |executions| {
                            executions.remove(contract);
                            executions.is_empty()
                        });

                    if is_empty {
                        self.scheduled_executions_per_topoheight.remove(&exec_topo);
                    }
                });
            });
        Ok(())
    }

    async fn delete_scheduled_executions_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let topoheight = topoheight + 1;
        self.contracts.iter_mut()
            .for_each(|(contract, contract_data)| {
                contract_data.scheduled_executions.split_off(&topoheight)
                .into_iter()
                .flat_map(|(_, entries)| entries.into_keys())
                .for_each(|exec_topo| {
                    let is_empty = self.scheduled_executions_per_topoheight.get_mut(&exec_topo)
                        .map_or(false, |executions| {
                            executions.remove(contract);
                            executions.is_empty()
                        });

                    if is_empty {
                        self.scheduled_executions_per_topoheight.remove(&exec_topo);
                    }
                });
            });

        Ok(())
    }

    async fn delete_scheduled_executions_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.contracts.iter_mut()
            .for_each(|(contract, contract_data)| {
                let to_keep = contract_data.scheduled_executions.split_off(&topoheight);

                // Delete only the planned scheduled executions that were executed below the topoheight
                // and remove the corresponding entries in scheduled_executions_per_topoheight.
                contract_data.scheduled_executions
                    .iter()
                    .flat_map(|(_, entries)| entries.keys())
                    .for_each(|exec_topo| {
                        let is_empty = self.scheduled_executions_per_topoheight.get_mut(exec_topo)
                            .map_or(false, |executions| {
                                executions.remove(contract);
                                executions.is_empty()
                            });

                        if is_empty {
                            self.scheduled_executions_per_topoheight.remove(exec_topo);
                        }
                    });

                contract_data.scheduled_executions = to_keep;
            });
        Ok(())
    }
}
