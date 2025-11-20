use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{contract::ContractModule, serializer::*};
use super::Deposits;

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct InvokeConstructorPayload {
    pub max_gas: u64,
    // Assets deposited with this call
    pub deposits: Deposits,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct DeployContractPayload {
    #[serde(flatten)]
    pub contract: ContractModule,
    pub invoke: Option<InvokeConstructorPayload>,
}

impl Serializer for DeployContractPayload {
    fn write(&self, writer: &mut Writer) {
        self.contract.write(writer);
        self.invoke.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> { 
        Ok(Self {
            contract: ContractModule::read(reader)?,
            invoke: Option::read(reader)?
        })
    }

    fn size(&self) -> usize {
        self.contract.size() + self.invoke.size()
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
            deposits: Deposits::read(reader)?,
        })
    }

    fn size(&self) -> usize {
        self.max_gas.size() + self.deposits.size()
    }
}