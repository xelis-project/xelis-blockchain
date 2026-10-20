use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    contract::ContractModule,
    serializer::{Error as SerializationError, *},
};
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
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.contract.write(writer)?;
            self.invoke.write(writer)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {

            Ok(Self {
                contract: ContractModule::read(reader)?,
                invoke: Option::read(reader)?
            })
        })
    }

    fn size(&self) -> usize {
        self.contract.size() + self.invoke.size()
    }
}

impl Serializer for InvokeConstructorPayload {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.max_gas.write(writer)?;
            self.deposits.write(writer)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {

            Ok(Self {
                max_gas: u64::read(reader)?,
                deposits: Deposits::read(reader)?,
            })
        })
    }

    fn size(&self) -> usize {
        self.max_gas.size() + self.deposits.size()
    }
}