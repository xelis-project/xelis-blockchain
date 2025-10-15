use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use log::trace;
use xelis_common::{block::TopoHeight, contract::ScheduledExecution, crypto::Hash, serializer::Serializer};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{ContractScheduledExecutionProvider, SledStorage}
};

#[async_trait]
impl ContractScheduledExecutionProvider for SledStorage {
    // Set contract scheduled execution at provided topoheight
    // Caller must ensures that the topoheight configured is >= current topoheight & no other execution was there
    // otherwise, it will get overwritted
    async fn set_contract_scheduled_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &ScheduledExecution, execution_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set contract {} scheduled execution at topoheight {}", contract, topoheight);

        let execution_key = Self::get_contract_scheduled_execution_key(contract, execution_topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_scheduled_executions, &execution_key, execution.to_bytes())?;

        // The execution key is stored in the registrations tree so we can easily clean up and iterate over it
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_scheduled_executions_registrations, &Self::get_contract_scheduled_execution_registration_key(topoheight, contract, execution_topoheight), &[])?;

        Ok(())
    }

    // Has a contract scheduled execution registered at the provided topoheight?
    // only one scheduled execution per contract and per topoheight can exist.
    async fn has_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} scheduled execution at topoheight {}", contract, topoheight);
        let key = Self::get_contract_scheduled_execution_key(contract, topoheight);
        self.contains_data(&self.contracts_scheduled_executions, &key)
    }

    async fn get_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<ScheduledExecution, BlockchainError> {
        trace!("get contract {} scheduled execution at topoheight {}", contract, topoheight);
        let key = Self::get_contract_scheduled_execution_key(contract, topoheight);
        self.load_from_disk(&self.contracts_scheduled_executions, &key, DiskContext::ScheduledExecution(topoheight))
    }

    async fn get_registered_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get registered contract scheduled executions at topoheight {}", topoheight);

        // Iterate over the registrations to get all the registrations done at provided topoheight
        let prefix = topoheight.to_be_bytes();
        Ok(Self::scan_prefix_keys(self.snapshot.as_ref(), &self.contracts_scheduled_executions_registrations, &prefix)    
            .map(|res| {
                let key = res?;

                // First topoheight is the same as the one passed in param
                // so we skip it
                let (contract, topoheight) = <(Hash, TopoHeight)>::from_bytes(&key[8..])?;

                Ok((topoheight, contract))
            })
        )
    }

    async fn get_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get contract scheduled executions at topoheight {}", topoheight);

        // Iterate over the planned executions topoheight
        let prefix = topoheight.to_be_bytes();
        Ok(Self::scan_prefix(self.snapshot.as_ref(), &self.contracts_scheduled_executions, &prefix)    
            .map(|res| {
                let (_, value) = res?;

                let execution = ScheduledExecution::from_bytes(&value)?;
                Ok(execution)
            })
        )
    }

    // Get the registered scheduled executions at maximum topoheight (inclusive)
    // Returns a stream of (execution_topoheight, registration_topoheight, execution)
    async fn get_registered_contract_scheduled_executions_at_maximum_topoheight<'a>(&'a self, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<impl Stream<Item = Result<(TopoHeight, TopoHeight, ScheduledExecution), BlockchainError>> + Send + 'a, BlockchainError> {
        trace!("get registered contract scheduled executions at maximum topoheight {}", maximum_topoheight);

        let stream = stream::iter(Self::iter_keys(self.snapshot.as_ref(), &self.contracts_scheduled_executions_registrations))
            .map(move |res| async move {
                let key = res?;

                let registration_topoheight = TopoHeight::from_bytes(&key)?;
                if registration_topoheight <= maximum_topoheight && registration_topoheight >= minimum_topoheight {
                    let (contract, execution_topoheight) = <(Hash, TopoHeight)>::from_bytes(&key[8..])?;
                    let execution = self.get_contract_scheduled_execution_at_topoheight(&contract, execution_topoheight).await?;
                    Ok(Some((execution_topoheight, registration_topoheight, execution)))
                } else {
                    Ok(None)
                }
            })
            .filter_map(|v| async { v.await.transpose() });

        Ok(stream)
    }
}

impl SledStorage {
    pub fn get_contract_scheduled_execution_key(contract: &Hash, topoheight: TopoHeight) -> [u8; 40] {
        let mut buf = [0; 40];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..].copy_from_slice(contract.as_bytes());

        buf
    }

    pub fn get_contract_scheduled_execution_registration_key(registration_topoheight: TopoHeight, contract: &Hash, execution_topoheight: TopoHeight) -> [u8; 48] {
        let mut buf = [0; 48];
        buf[0..8].copy_from_slice(&registration_topoheight.to_be_bytes());
        buf[8..40].copy_from_slice(contract.as_bytes());
        buf[40..].copy_from_slice(&execution_topoheight.to_be_bytes());

        buf
    }
}