use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use xelis_common::{
    block::TopoHeight,
    contract::ScheduledExecution,
    crypto::Hash,
    serializer::Serializer,
    versioned::Versioned
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{ContractScheduledExecutionProvider, SledStorage, VersionedScheduledExecution}
};

#[async_trait]
impl ContractScheduledExecutionProvider for SledStorage {
    async fn get_last_contract_scheduled_execution_registration_topoheight(&self, contract: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        self.load_optional_from_disk(&self.contract_scheduled_execution_pointers, contract.as_bytes())
    }

    async fn set_last_contract_scheduled_execution_at_registration_topoheight(&mut self, contract: &Hash, registration_topoheight: TopoHeight, version: &VersionedScheduledExecution) -> Result<(), BlockchainError> {
        let version_key = Self::get_versioned_key(contract.as_bytes(), registration_topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_contracts_scheduled_executions, &version_key, version.to_bytes())?;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contract_scheduled_execution_pointers, contract.as_bytes(), &registration_topoheight.to_be_bytes())?;
        if let Some(target) = version.get().kind.execution_topoheight() {
            Self::insert_into_disk(self.snapshot.as_mut(), &self.scheduled_execution_index, &Self::get_scheduled_execution_index_key(contract, target), &registration_topoheight.to_be_bytes())?;
        }
        Ok(())
    }

    async fn get_contract_scheduled_execution_at_exact_registration_topoheight(&self, contract: &Hash, registration_topoheight: TopoHeight) -> Result<VersionedScheduledExecution, BlockchainError> {
        let key = Self::get_versioned_key(contract.as_bytes(), registration_topoheight);
        self.load_from_disk(&self.versioned_contracts_scheduled_executions, &key, DiskContext::ScheduledExecution(registration_topoheight))
    }

    async fn has_contract_scheduled_execution_at_exact_registration_topoheight(&self, contract: &Hash, registration_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let key = Self::get_versioned_key(contract.as_bytes(), registration_topoheight);
        self.contains_data(&self.versioned_contracts_scheduled_executions, key)
    }

    async fn has_contract_scheduled_execution_at_execution_topoheight(&self, contract: &Hash, execution_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        self.contains_data(&self.scheduled_execution_index, Self::get_scheduled_execution_index_key(contract, execution_topoheight))
    }

    async fn set_contract_scheduled_execution_at_registration_topoheight(&mut self, contract: &Hash, registration_topoheight: TopoHeight, execution: &ScheduledExecution) -> Result<(), BlockchainError> {
        let previous = self.get_last_contract_scheduled_execution_registration_topoheight(contract).await?;
        let version = Versioned::new(execution.clone(), previous);
        self.set_last_contract_scheduled_execution_at_registration_topoheight(contract, registration_topoheight, &version).await
    }

    async fn get_contract_scheduled_execution_at_execution_topoheight(&self, contract: &Hash, execution_topoheight: TopoHeight) -> Result<Option<ScheduledExecution>, BlockchainError> {
        let key = Self::get_scheduled_execution_index_key(contract, execution_topoheight);
        let Some(registration_topoheight) = self.load_optional_from_disk::<TopoHeight, _>(&self.scheduled_execution_index, key)? else { return Ok(None); };
        let version = self.get_contract_scheduled_execution_at_exact_registration_topoheight(contract, registration_topoheight).await?;
        Ok(Some(version.take()))
    }

    async fn get_contracts_with_scheduled_executions_at_execution_topoheight<'a>(&'a self, execution_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + Send + 'a, BlockchainError> {
        let prefix = execution_topoheight.to_be_bytes();
        Ok(Self::scan_prefix_keys::<(TopoHeight, Hash)>(self.snapshot.as_ref(), &self.scheduled_execution_index, &prefix).map(|res| res.map(|(_, contract)| contract)))
    }

    async fn get_contract_scheduled_executions_at_registration_topoheight<'a>(&'a self, registration_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError> {
        let prefix = registration_topoheight.to_be_bytes();
        let executions = Self::scan_prefix_keys::<(TopoHeight, Hash)>(self.snapshot.as_ref(), &self.versioned_contracts_scheduled_executions, &prefix)
            .map(move |res| {
                let (_, contract) = res?;
                let key = Self::get_versioned_key(contract.as_bytes(), registration_topoheight);
                let version = self.load_from_disk::<VersionedScheduledExecution, _>(&self.versioned_contracts_scheduled_executions, key, DiskContext::ScheduledExecution(registration_topoheight))?;
                let target = version.get().kind.execution_topoheight().unwrap_or(registration_topoheight);
                Ok((target, contract))
            });
        Ok(executions)
    }

    async fn get_contract_scheduled_executions_at_execution_topoheight<'a>(&'a self, execution_topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError> {
        let executions = Self::scan_prefix_keys::<(TopoHeight, Hash)>(self.snapshot.as_ref(), &self.scheduled_execution_index, &execution_topoheight.to_be_bytes())
            .map(move |res| {
                let (target, contract) = res?;
                let registration_topoheight = self.load_from_disk::<TopoHeight, _>(&self.scheduled_execution_index, Self::get_scheduled_execution_index_key(&contract, target), DiskContext::ScheduledExecution(target))?;
                let version_key = Self::get_versioned_key(contract.as_bytes(), registration_topoheight);
                let version = self.load_from_disk::<VersionedScheduledExecution, _>(&self.versioned_contracts_scheduled_executions, version_key, DiskContext::ScheduledExecution(registration_topoheight))?;
                Ok(version.take())
            });
        Ok(executions)
    }

    async fn get_contract_scheduled_executions_in_registration_topoheight_range<'a>(&'a self, minimum_registration_topoheight: TopoHeight, maximum_registration_topoheight: TopoHeight, min_execution_topoheight: Option<TopoHeight>) -> Result<impl Stream<Item = Result<(TopoHeight, TopoHeight, ScheduledExecution), BlockchainError>> + Send + 'a, BlockchainError> {
        let stream = stream::iter(Self::iter_keys::<(TopoHeight, Hash)>(self.snapshot.as_ref(), &self.versioned_contracts_scheduled_executions))
            .map(move |res| async move {
                let (registration_topoheight, contract) = res?;
                if registration_topoheight < minimum_registration_topoheight || registration_topoheight > maximum_registration_topoheight {
                    return Ok(None);
                }
                let version = self.get_contract_scheduled_execution_at_exact_registration_topoheight(&contract, registration_topoheight).await?;
                let Some(execution_topoheight) = version.get().kind.execution_topoheight() else { return Ok(None); };
                if min_execution_topoheight.is_some_and(|min| execution_topoheight < min) {
                    return Ok(None);
                }
                Ok(Some((execution_topoheight, registration_topoheight, version.take())))
            })
            .filter_map(|res| async { res.await.transpose() });
        Ok(stream)
    }
}

impl SledStorage {
    pub fn get_scheduled_execution_index_key(contract: &Hash, execution_topoheight: TopoHeight) -> [u8; 40] {
        let mut buf = [0; 40];
        buf[0..8].copy_from_slice(&execution_topoheight.to_be_bytes());
        buf[8..].copy_from_slice(contract.as_bytes());
        buf
    }
}