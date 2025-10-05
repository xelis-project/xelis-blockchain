use async_trait::async_trait;
use log::trace;
use xelis_common::{block::TopoHeight, contract::DelayedExecution, crypto::Hash};
use crate::core::{
    error::BlockchainError,
    storage::{rocksdb::{Column, ContractId}, ContractDelayedExecutionProvider, RocksStorage}
};

#[async_trait]
impl ContractDelayedExecutionProvider for RocksStorage {
    // Set contract delayed execution at provided topoheight
    // Caller must ensures that the topoheight configured is >= current topoheight & no other execution was there
    // otherwise, it will get overwritted
    async fn set_contract_delayed_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &DelayedExecution) -> Result<(), BlockchainError> {
        trace!("set contract {} delayed execution at topoheight {}", contract, topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_contract_delayed_execution_key(contract_id, topoheight);

        self.insert_into_disk(Column::DelayedExecution, &key, execution)
    }

    // Has a contract delayed execution registered at the provided topoheight?
    // only one delayed execution per contract and per topoheight can exist.
    async fn has_contract_delayed_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} delayed execution at topoheight {}", contract, topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_contract_delayed_execution_key(contract_id, topoheight);

        self.contains_data(Column::DelayedExecution, &key)
    }

    async fn get_contract_delayed_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<DelayedExecution, BlockchainError> {
        trace!("get contract {} delayed execution at topoheight {}", contract, topoheight);

        let contract_id = self.get_contract_id(contract)?;
        let key = Self::get_contract_delayed_execution_key(contract_id, topoheight);

        self.load_from_disk(Column::DelayedExecution, &key)
    }
}

impl RocksStorage {
    pub fn get_contract_delayed_execution_key(contract: ContractId, topoheight: TopoHeight) -> [u8; 16] {
        let mut buf = [0; 16];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..].copy_from_slice(&contract.to_be_bytes());

        buf
    }
}