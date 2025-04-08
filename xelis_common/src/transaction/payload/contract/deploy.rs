use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use xelis_vm::Module;

use crate::{crypto::Hash, serializer::*};
use super::ContractDeposit;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InvokeConstructorPayload {
    pub max_gas: u64,
    // Assets deposited with this call
    pub deposits: IndexMap<Hash, ContractDeposit>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeployContractPayload {
    pub module: Module,
    pub invoke: Option<InvokeConstructorPayload>,
}

impl Serializer for DeployContractPayload {
    fn write(&self, writer: &mut Writer) {
        self.module.write(writer);
        self.invoke.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> { 
        Ok(Self {
            module: Module::read(reader)?,
            invoke: Option::read(reader)?
        })
    }

    fn size(&self) -> usize {
        self.module.size() + self.invoke.size()
    }
}

impl Serializer for InvokeConstructorPayload {
    fn write(&self, writer: &mut Writer) {
        self.max_gas.write(writer);
        self.deposits.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> { 
        Ok(Self {
            max_gas: u64::read(reader)?,
            deposits: IndexMap::read(reader)?
        })
    }

    fn size(&self) -> usize {
        self.max_gas.size() + self.deposits.size()
    }
}