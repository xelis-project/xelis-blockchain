use async_trait::async_trait;
use futures::{stream, Stream};
use log::trace;
use xelis_common::{block::TopoHeight, contract::ScheduledExecution, crypto::Hash};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{Column, ContractId, IteratorMode},
        snapshot::Direction,
        ContractScheduledExecutionProvider,
        RocksStorage
    }
};

#[async_trait]
impl ContractScheduledExecutionProvider for RocksStorage {
    // Set contract scheduled execution at provided topoheight
    // Caller must ensures that the topoheight configured is >= current topoheight & no other execution was there
    // otherwise, it will get overwritted
    async fn set_contract_scheduled_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &ScheduledExecution, execution_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set contract {} scheduled execution at topoheight {}", contract, execution_topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_contract_scheduled_execution_key(contract_id, execution_topoheight);
        self.insert_into_disk(Column::DelayedExecution, &key, execution)?;

        let key = Self::get_contract_scheduled_execution_registration_key(topoheight, contract_id, execution_topoheight);
        self.insert_into_disk(Column::DelayedExecutionRegistrations, &key, &[])
    }

    // Has a contract scheduled execution registered at the provided topoheight?
    // only one scheduled execution per contract and per topoheight can exist.
    async fn has_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} scheduled execution at topoheight {}", contract, topoheight);

        let Some(contract_id) = self.get_optional_contract_id(contract)? else {
            return Ok(false);
        };
        let key = Self::get_contract_scheduled_execution_key(contract_id, topoheight);

        self.contains_data(Column::DelayedExecution, &key)
    }

    async fn get_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<ScheduledExecution, BlockchainError> {
        trace!("get contract {} scheduled execution at topoheight {}", contract, topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_contract_scheduled_execution_key(contract_id, topoheight);

        self.load_from_disk(Column::DelayedExecution, &key)
    }

    async fn get_registered_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<(TopoHeight, Hash), BlockchainError>> + Send + 'a, BlockchainError> {
        let prefix = topoheight.to_be_bytes();
        self.iter_keys::<(TopoHeight, ContractId, TopoHeight)>(Column::DelayedExecutionRegistrations, IteratorMode::WithPrefix(&prefix, Direction::Forward))
            .map(|iter| iter.map(|res| {
                let (_, contract_id, topoheight) = res?;
                let contract = self.get_contract_from_id(contract_id)?;
                Ok((topoheight, contract))
            }))
    }

    async fn get_contract_scheduled_executions_at_topoheight<'a>(&'a self, topoheight: TopoHeight) -> Result<impl Iterator<Item = Result<ScheduledExecution, BlockchainError>> + Send + 'a, BlockchainError> {
        let prefix = topoheight.to_be_bytes();
        self.iter::<(), ScheduledExecution>(Column::DelayedExecution, IteratorMode::WithPrefix(&prefix, Direction::Forward))
            .map(|iter| iter.map(|res| res.map(|(_, v)| v)))
    }

    async fn get_registered_contract_scheduled_executions_in_range<'a>(&'a self, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<impl Stream<Item = Result<(TopoHeight, TopoHeight, ScheduledExecution), BlockchainError>> + Send + 'a, BlockchainError> {
        let min = minimum_topoheight.to_be_bytes();
        let max = (maximum_topoheight + 1).to_be_bytes();
        let stream = self.iter_keys::<(TopoHeight, ContractId, TopoHeight)>(Column::DelayedExecutionRegistrations, IteratorMode::Range {
            lower_bound: &min,
            upper_bound: &max,
            direction: Direction::Reverse
        })?
            .map(move |res| {
                let (registration, contract_id, execution_topoheight) = res?;
                if registration <= maximum_topoheight && registration >= minimum_topoheight {
                    let key = Self::get_contract_scheduled_execution_key(contract_id, execution_topoheight);
                    let execution = self.load_from_disk(Column::DelayedExecution, &key)?;

                    Ok(Some((execution_topoheight, registration, execution)))
                } else {
                    Ok(None)
                }
            })
            .filter_map(Result::transpose);

        Ok(stream::iter(stream))
    }
}

impl RocksStorage {
    pub fn get_contract_scheduled_execution_key(contract: ContractId, topoheight: TopoHeight) -> [u8; 16] {
        let mut buf = [0; 16];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..].copy_from_slice(&contract.to_be_bytes());

        buf
    }

    pub fn get_contract_scheduled_execution_registration_key(topoheight: TopoHeight, contract: ContractId, execution_topoheight: TopoHeight) -> [u8; 24] {
        let mut buf = [0; 24];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..16].copy_from_slice(&contract.to_be_bytes());
        buf[16..].copy_from_slice(&execution_topoheight.to_be_bytes());

        buf
    }
}