use async_trait::async_trait;
use log::trace;
use xelis_common::{block::TopoHeight, contract::DelayedExecution, crypto::Hash, serializer::Serializer};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{ContractDelayedExecutionProvider, SledStorage}
};

#[async_trait]
impl ContractDelayedExecutionProvider for SledStorage {
    // Set contract delayed execution at provided topoheight
    // Caller must ensures that the topoheight configured is >= current topoheight & no other execution was there
    // otherwise, it will get overwritted
    async fn set_contract_delayed_execution_at_topoheight(&mut self, contract: &Hash, topoheight: TopoHeight, execution: &DelayedExecution) -> Result<(), BlockchainError> {
        trace!("set contract {} delayed execution at topoheight {}", contract, topoheight);

        let key = Self::get_contract_delayed_execution_key(contract, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.contracts_delayed_executions, &key, execution.to_bytes())?;
        Ok(())
    }

    // Has a contract delayed execution registered at the provided topoheight?
    // only one delayed execution per contract and per topoheight can exist.
    async fn has_contract_delayed_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has contract {} delayed execution at topoheight {}", contract, topoheight);
        let key = Self::get_contract_delayed_execution_key(contract, topoheight);
        self.contains_data(&self.contracts_delayed_executions, &key)
    }

    async fn get_contract_delayed_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<DelayedExecution, BlockchainError> {
        trace!("get contract {} delayed execution at topoheight {}", contract, topoheight);
        let key = Self::get_contract_delayed_execution_key(contract, topoheight);
        self.load_from_disk(&self.contracts_delayed_executions, &key, DiskContext::DelayedExecution(topoheight))
    }
}

impl SledStorage {
    pub fn get_contract_delayed_execution_key(contract: &Hash, topoheight: TopoHeight) -> [u8; 40] {
        let mut buf = [0; 40];
        buf[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buf[8..].copy_from_slice(contract.as_bytes());

        buf
    }
}