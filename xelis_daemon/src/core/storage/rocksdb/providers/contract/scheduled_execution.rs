use async_trait::async_trait;
use futures::{stream, Stream};
use xelis_common::{
    block::TopoHeight,
    contract::ScheduledExecution,
    crypto::Hash,
    versioned::Versioned
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, ContractId, IteratorMode},
        snapshot::Direction,
        ContractScheduledExecutionProvider,
        VersionedScheduledExecution,
        RocksStorage
    }
};

#[async_trait]
impl ContractScheduledExecutionProvider for RocksStorage {
    async fn get_last_contract_scheduled_execution_registration_topoheight(&self, contract: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        self.get_optional_contract_type(contract).map(|record| record.and_then(|contract| contract.scheduled_execution_pointer))
    }

    async fn set_last_contract_scheduled_execution_at_registration_topoheight(&mut self, contract: &Hash, registration_topoheight: TopoHeight, version: &VersionedScheduledExecution) -> Result<(), BlockchainError> {
        let mut record = self.get_or_create_contract_type(contract)?;
        record.scheduled_execution_pointer = Some(registration_topoheight);
        self.insert_into_disk(Column::VersionedContractScheduledExecutions, &Self::get_versioned_contract_scheduled_execution_key(record.id, registration_topoheight), version)?;
        self.insert_into_disk(Column::Contracts, contract, &record)?;
        if let Some(target) = version.get().kind.execution_topoheight() {
            self.insert_into_disk(Column::ScheduledExecutionIndex, &Self::get_scheduled_execution_index_key(record.id, target), &registration_topoheight)?;
        }
        Ok(())
    }

    async fn get_contract_scheduled_execution_at_exact_registration_topoheight(&self, contract: &Hash, registration_topoheight: TopoHeight) -> Result<VersionedScheduledExecution, BlockchainError> {
        let contract_id = self.get_contract_id(contract)?;
        self.load_from_disk(Column::VersionedContractScheduledExecutions, &Self::get_versioned_contract_scheduled_execution_key(contract_id, registration_topoheight))
    }

    async fn has_contract_scheduled_execution_at_exact_registration_topoheight(&self, contract: &Hash, registration_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let Some(contract_id) = self.get_optional_contract_id(contract)? else { return Ok(false); };
        self.contains_data(Column::VersionedContractScheduledExecutions, &Self::get_versioned_contract_scheduled_execution_key(contract_id, registration_topoheight))
    }

    async fn has_contract_scheduled_execution_at_execution_topoheight(&self, contract: &Hash, execution_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let Some(contract_id) = self.get_optional_contract_id(contract)? else { return Ok(false); };
        self.contains_data(Column::ScheduledExecutionIndex, &Self::get_scheduled_execution_index_key(contract_id, execution_topoheight))
    }

    async fn set_contract_scheduled_execution_at_registration_topoheight(&mut self, contract: &Hash, registration_topoheight: TopoHeight, execution: &ScheduledExecution) -> Result<(), BlockchainError> {
        let previous = self.get_last_contract_scheduled_execution_registration_topoheight(contract).await?;
        let version = Versioned::new(execution.clone(), previous);
        self.set_last_contract_scheduled_execution_at_registration_topoheight(contract, registration_topoheight, &version).await
    }

    async fn get_contract_scheduled_execution_at_execution_topoheight(&self, contract: &Hash, execution_topoheight: TopoHeight) -> Result<Option<ScheduledExecution>, BlockchainError> {
        let Some(contract_id) = self.get_optional_contract_id(contract)? else { return Ok(None); };
        let key = Self::get_scheduled_execution_index_key(contract_id, execution_topoheight);
        let Some(registration_topoheight) = self.load_optional_from_disk::<_, TopoHeight>(Column::ScheduledExecutionIndex, &key)? else { return Ok(None); };
        let version = self.get_contract_scheduled_execution_at_exact_registration_topoheight(contract, registration_topoheight).await?;
        Ok(Some(version.take()))
    }

    async fn get_contracts_with_scheduled_executions_at_execution_topoheight<'a>(&'a self, execution_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + Send + 'a, BlockchainError> {
        let prefix = execution_topoheight.to_be_bytes();
        self.iter_keys::<(TopoHeight, ContractId)>(Column::ScheduledExecutionIndex, IteratorMode::WithPrefix(&prefix, Direction::Forward))
            .map(|iter| iter.map(|res| { let (_, id) = res?; self.get_contract_from_id(id) }))
    }

    async fn get_contract_scheduled_executions_at_registration_topoheight<'a>(&'a self, registration_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError> {
        let prefix = registration_topoheight.to_be_bytes();
        self.iter_keys::<(TopoHeight, ContractId)>(Column::VersionedContractScheduledExecutions, IteratorMode::WithPrefix(&prefix, Direction::Forward))
            .map(move |iter| iter.map(move |res| {
                let (_, id) = res?;
                let contract = self.get_contract_from_id(id)?;
                let version = self.load_from_disk::<_, VersionedScheduledExecution>(Column::VersionedContractScheduledExecutions, &Self::get_versioned_contract_scheduled_execution_key(id, registration_topoheight))?;
                Ok((version.get().kind.execution_topoheight().unwrap_or(registration_topoheight), contract))
            }))
    }

    async fn get_contract_scheduled_executions_at_execution_topoheight<'a>(&'a self, execution_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError> {
        let prefix = execution_topoheight.to_be_bytes();
        self.iter_keys::<(TopoHeight, ContractId)>(Column::ScheduledExecutionIndex, IteratorMode::WithPrefix(&prefix, Direction::Forward))
            .map(move |iter| iter.map(move |res| {
                let (_, id) = res?;
                let registration = self.load_from_disk::<_, TopoHeight>(Column::ScheduledExecutionIndex, &Self::get_scheduled_execution_index_key(id, execution_topoheight))?;
                let version = self.load_from_disk::<_, VersionedScheduledExecution>(Column::VersionedContractScheduledExecutions, &Self::get_versioned_contract_scheduled_execution_key(id, registration))?;
                Ok(version.take())
            }))
    }

    async fn get_contract_scheduled_executions_in_registration_topoheight_range<'a>(&'a self, minimum_registration_topoheight: TopoHeight, maximum_registration_topoheight: TopoHeight, min_execution_topoheight: Option<TopoHeight>) -> Result<impl Stream<Item = Result<(TopoHeight, TopoHeight, ScheduledExecution), BlockchainError>> + Send + 'a, BlockchainError> {
        let min = minimum_registration_topoheight.to_be_bytes();
        let max = maximum_registration_topoheight.checked_add(1).unwrap_or(TopoHeight::MAX).to_be_bytes();
        let iterator = self.iter_keys::<(TopoHeight, ContractId)>(Column::VersionedContractScheduledExecutions, IteratorMode::Range {
            lower_bound: Some(&min), upper_bound: Some(&max), direction: Direction::Reverse
        })?;
        let stream = iterator.map(move |res| {
            let (registration, id) = res?;
            let version = self.load_from_disk::<_, VersionedScheduledExecution>(Column::VersionedContractScheduledExecutions, &Self::get_versioned_contract_scheduled_execution_key(id, registration))?;
            let Some(target) = version.get().kind.execution_topoheight() else { return Ok(None); };
            if min_execution_topoheight.is_some_and(|min| target < min) { return Ok(None); }
            Ok(Some((target, registration, version.take())))
        }).filter_map(Result::transpose);
        Ok(stream::iter(stream))
    }
}

impl RocksStorage {
    pub fn get_versioned_contract_scheduled_execution_key(contract: ContractId, registration_topoheight: TopoHeight) -> [u8; 16] {
        let mut buf = [0; 16];
        buf[0..8].copy_from_slice(&registration_topoheight.to_be_bytes());
        buf[8..].copy_from_slice(&contract.to_be_bytes());
        buf
    }

    pub fn get_scheduled_execution_index_key(contract: ContractId, execution_topoheight: TopoHeight) -> [u8; 16] {
        let mut buf = [0; 16];
        buf[0..8].copy_from_slice(&execution_topoheight.to_be_bytes());
        buf[8..].copy_from_slice(&contract.to_be_bytes());
        buf
    }
}