use async_trait::async_trait;
use log::trace;
use rocksdb::Direction;
use xelis_common::{block::TopoHeight, contract::ScheduledExecution, crypto::Hash};
use crate::core::{
    error::BlockchainError,
    storage::{rocksdb::{Column, ContractId, IteratorMode}, ContractScheduledExecutionProvider, RocksStorage}
};

#[async_trait]
impl ContractScheduledExecutionProvider for RocksStorage {
    // Set contract delayed execution at provided topoheight
    // Caller must ensures that the topoheight configured is >= current topoheight & no other execution was there
    // otherwise, it will get overwritted
    async fn set_contract_scheduled_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &ScheduledExecution, execution_topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set contract {} delayed execution at topoheight {}", contract, execution_topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_contract_scheduled_execution_key(contract_id, execution_topoheight);
        self.insert_into_disk(Column::DelayedExecution, &key, execution)?;

        let key = Self::get_contract_scheduled_execution_registration_key(topoheight, contract_id, execution_topoheight);
        self.insert_into_disk(Column::DelayedExecutionRegistrations, &key, &[])
    }

    // Has a contract delayed execution registered at the provided topoheight?
    // only one delayed execution per contract and per topoheight can exist.
    async fn has_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} delayed execution at topoheight {}", contract, topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_contract_scheduled_execution_key(contract_id, topoheight);

        self.contains_data(Column::DelayedExecution, &key)
    }

    async fn get_contract_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<ScheduledExecution, BlockchainError> {
        trace!("get contract {} delayed execution at topoheight {}", contract, topoheight);

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