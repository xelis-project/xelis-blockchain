use anyhow::Context;
use pooled_arc::PooledArc;
use async_trait::async_trait;
use futures::stream;
use xelis_common::{
    block::TopoHeight,
    contract::ScheduledExecution,
    crypto::Hash,
};
use futures::Stream;
use crate::core::{
    error::BlockchainError,
    storage::ContractScheduledExecutionProvider,
};
use super::super::super::MemoryStorage;

#[async_trait]
impl ContractScheduledExecutionProvider for MemoryStorage {
    async fn set_contract_scheduled_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &ScheduledExecution, execution_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(contract);
        self.contracts
            .entry(shared.clone())
            .or_default()
            .scheduled_executions
            .entry(topoheight)
            .or_default()
            .insert(execution_topoheight, execution.clone());

        self.scheduled_executions_per_topoheight
            .entry(execution_topoheight)
            .or_default()
            .insert(shared, topoheight);

        Ok(())
    }

    async fn has_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.scheduled_executions_per_topoheight.get(&topoheight)
            .map_or(false, |executions| executions.contains_key(contract))
        )
    }

    async fn get_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<ScheduledExecution, BlockchainError> {
        self.scheduled_executions_per_topoheight.get(&topoheight)
            .and_then(|executions| executions.get(contract))
            .and_then(|&reg_topo| self.contracts.get(contract)
                .and_then(|contract_data| contract_data.scheduled_executions.get(&reg_topo))
                .and_then(|executions_at_topo| executions_at_topo.get(&topoheight))
            )
            .cloned()
            .with_context(|| format!("Scheduled execution not found for contract {} at topoheight {}", contract, topoheight))
            .map_err(|e| e.into())
    }

    async fn get_contract_scheduled_executions_for_execution_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(self.scheduled_executions_per_topoheight.get(&topoheight)
            .into_iter()
            .flat_map(|executions| executions.keys())
            .map(|contract| Ok(contract.as_ref().clone()))
        )
    }

    async fn get_registered_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(self.contracts.iter()
            .flat_map(move |(contract, contract_data)| contract_data.scheduled_executions.get(&topoheight)
                .into_iter()
                .flat_map(move |executions| executions.iter()
                    .map(move |(&exec_topo, _)| Ok((exec_topo, contract.as_ref().clone()))))
            )
        )
    }

    async fn get_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(self.scheduled_executions_per_topoheight.get(&topoheight)
            .into_iter()
            .flat_map(|executions| executions.iter())
            .filter_map(move |(contract, reg_topo)| {
                self.contracts.get(contract)
                    .and_then(|contract_data| contract_data.scheduled_executions.get(reg_topo))
                    .and_then(|executions_at_topo| executions_at_topo.get(&topoheight))
                    .cloned()
            })
            .map(Ok)
        )
    }

    // Returns a stream of (execution_topoheight, registration_topoheight, execution)
    async fn get_registered_contract_scheduled_executions_in_range<'a>(&'a self, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight, min_execution_topoheight: Option<TopoHeight>) -> Result<impl Stream<Item = Result<(TopoHeight, TopoHeight, ScheduledExecution), BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(stream::iter(self.contracts.iter()
            .flat_map(move |(_, contract_data)| contract_data.scheduled_executions.range(minimum_topoheight..=maximum_topoheight)
                .flat_map(move |(&reg_topo, executions_at_topo)| executions_at_topo.range(min_execution_topoheight.unwrap_or(0)..)
                    .filter_map(move |(&exec_topo, execution)| {
                        if min_execution_topoheight.map_or(true, |min_exec| exec_topo >= min_exec) {
                            Some(Ok((exec_topo, reg_topo, execution.clone())))
                        } else {
                            None
                        }
                    })
                )
            )))
    }
}
