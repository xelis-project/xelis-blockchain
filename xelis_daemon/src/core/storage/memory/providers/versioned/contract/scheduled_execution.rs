use async_trait::async_trait;
use xelis_common::block::TopoHeight;
use crate::core::{
    error::BlockchainError,
    storage::{VersionedScheduledExecutionsProvider, MemoryStorage},
};

#[async_trait]
impl VersionedScheduledExecutionsProvider for MemoryStorage {
    async fn delete_scheduled_executions_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        for (contract, contract_data) in self.state.contracts.iter_mut() {
            if let Some(entries) = contract_data.scheduled_executions.remove(&topoheight) {
                for exec_topo in entries.into_keys() {
                    let is_empty = self.state.scheduled_executions_per_topoheight.get_mut(&exec_topo)
                        .map_or(false, |executions| {
                            executions.remove(contract);
                            executions.is_empty()
                        });

                    if is_empty {
                        self.state.scheduled_executions_per_topoheight.remove(&exec_topo);
                    }
                }
            }
        }

        Ok(())
    }

    async fn delete_scheduled_executions_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let topoheight = topoheight + 1;
        self.state.contracts.iter_mut()
            .for_each(|(contract, contract_data)| {
                contract_data.scheduled_executions.split_off(&topoheight)
                .into_iter()
                .flat_map(|(_, entries)| entries.into_keys())
                .for_each(|exec_topo| {
                    let is_empty = self.state.scheduled_executions_per_topoheight.get_mut(&exec_topo)
                        .map_or(false, |executions| {
                            executions.remove(contract);
                            executions.is_empty()
                        });

                    if is_empty {
                        self.state.scheduled_executions_per_topoheight.remove(&exec_topo);
                    }
                });
            });

        Ok(())
    }

    async fn delete_scheduled_executions_below_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        for (contract, contract_data) in self.state.contracts.iter_mut() {
            let mut removed_exec_topos = Vec::new();

            contract_data.scheduled_executions.retain(|_, entries| {
                entries.retain(|exec_topo, _| {
                    if *exec_topo < topoheight {
                        removed_exec_topos.push(*exec_topo);
                        false
                    } else {
                        true
                    }
                });

                !entries.is_empty()
            });

            for exec_topo in removed_exec_topos {
                let is_empty = self.state.scheduled_executions_per_topoheight.get_mut(&exec_topo)
                    .map_or(false, |executions| {
                        executions.remove(contract);
                        executions.is_empty()
                    });

                if is_empty {
                    self.state.scheduled_executions_per_topoheight.remove(&exec_topo);
                }
            }
        }

        Ok(())
    }
}
