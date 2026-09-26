use anyhow::Context;
use pooled_arc::PooledArc;
use async_trait::async_trait;
use futures::{stream, Stream};
use xelis_common::{block::TopoHeight, contract::ScheduledExecution, crypto::Hash};
use crate::core::{
    error::BlockchainError,
    storage::{ContractScheduledExecutionProvider, VersionedScheduledExecution},
};
use super::super::super::MemoryStorage;

#[async_trait]
impl ContractScheduledExecutionProvider for MemoryStorage {
    async fn get_last_contract_scheduled_execution_registration_topoheight(&self, contract: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.contracts.get(contract).and_then(|entry| entry.scheduled_execution_pointer))
    }

    async fn set_last_contract_scheduled_execution_at_registration_topoheight(&mut self, contract: &Hash, registration_topoheight: TopoHeight, version: &VersionedScheduledExecution) -> Result<(), BlockchainError> {
        let entry = self.contracts.entry(PooledArc::from_ref(contract)).or_default();
        entry.scheduled_executions.insert(registration_topoheight, version.clone());
        entry.scheduled_execution_pointer = Some(registration_topoheight);
        if let Some(target) = version.get().kind.execution_topoheight() {
            self.scheduled_executions_per_topoheight.entry(target).or_default()
                .insert(PooledArc::from_ref(contract), registration_topoheight);
        }
        Ok(())
    }

    async fn get_contract_scheduled_execution_at_exact_registration_topoheight(&self, contract: &Hash, registration_topoheight: TopoHeight) -> Result<VersionedScheduledExecution, BlockchainError> {
        self.contracts.get(contract).and_then(|entry| entry.scheduled_executions.get(&registration_topoheight)).cloned()
            .with_context(|| format!("Scheduled execution not found for contract {} at registration topoheight {}", contract, registration_topoheight)).map_err(Into::into)
    }

    async fn has_contract_scheduled_execution_at_exact_registration_topoheight(&self, contract: &Hash, registration_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.contracts.get(contract).is_some_and(|entry| entry.scheduled_executions.contains_key(&registration_topoheight)))
    }

    async fn has_contract_scheduled_execution_at_execution_topoheight(&self, contract: &Hash, execution_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.scheduled_executions_per_topoheight.get(&execution_topoheight).is_some_and(|items| items.contains_key(contract)))
    }

    async fn set_contract_scheduled_execution_at_registration_topoheight(&mut self, contract: &Hash, registration_topoheight: TopoHeight, execution: &ScheduledExecution) -> Result<(), BlockchainError> {
        let previous = self.get_last_contract_scheduled_execution_registration_topoheight(contract).await?;
        let version = VersionedScheduledExecution::new(execution.clone(), previous);
        self.set_last_contract_scheduled_execution_at_registration_topoheight(contract, registration_topoheight, &version).await
    }

    async fn get_contract_scheduled_execution_at_execution_topoheight(&self, contract: &Hash, execution_topoheight: TopoHeight) -> Result<Option<ScheduledExecution>, BlockchainError> {
        let Some(registration_topoheight) = self.scheduled_executions_per_topoheight.get(&execution_topoheight).and_then(|items| items.get(contract)) else { return Ok(None); };
        Ok(Some(self.get_contract_scheduled_execution_at_exact_registration_topoheight(contract, *registration_topoheight).await?.get().clone()))
    }

    async fn get_contracts_with_scheduled_executions_at_execution_topoheight<'a>(&'a self, execution_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(self.scheduled_executions_per_topoheight.get(&execution_topoheight).into_iter().flat_map(|items| items.keys()).map(|contract| Ok(contract.as_ref().clone())))
    }

    async fn get_contract_scheduled_executions_at_registration_topoheight<'a>(&'a self, registration_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(self.contracts.iter().filter_map(move |(contract, entry)| {
            entry.scheduled_executions.get(&registration_topoheight).map(|version| {
                let target = version.get().kind.execution_topoheight().unwrap_or(registration_topoheight);
                Ok((target, contract.as_ref().clone()))
            })
        }))
    }

    async fn get_contract_scheduled_executions_at_execution_topoheight<'a>(&'a self, execution_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError> {
        Ok(self.scheduled_executions_per_topoheight.get(&execution_topoheight).into_iter().flat_map(|items| items.iter()).filter_map(move |(contract, registration)| {
            self.contracts.get(contract).and_then(|entry| entry.scheduled_executions.get(registration)).map(|version| Ok(version.get().clone()))
        }))
    }

    async fn get_contract_scheduled_executions_in_registration_topoheight_range<'a>(&'a self, minimum_registration_topoheight: TopoHeight, maximum_registration_topoheight: TopoHeight, min_execution_topoheight: Option<TopoHeight>) -> Result<impl Stream<Item = Result<(TopoHeight, TopoHeight, ScheduledExecution), BlockchainError>> + Send + 'a, BlockchainError> {
        let entries = self.contracts.values().flat_map(move |entry| {
            entry.scheduled_executions.range(minimum_registration_topoheight..=maximum_registration_topoheight).filter_map(move |(&registration, version)| {
                let execution_topoheight = version.get().kind.execution_topoheight().unwrap_or(registration);
                if min_execution_topoheight.is_none_or(|min| execution_topoheight >= min) {
                    Some(Ok((execution_topoheight, registration, version.get().clone())))
                } else {
                    None
                }
            })
        });
        Ok(stream::iter(entries))
    }
}
