use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::Module;

use crate::serializer::*;

#[derive(Default, Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ContractVersion {
    #[default]
    V1,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContractModule {
    pub version: ContractVersion,
    // keep it behind Arc to reduce cloning overhead
    pub module: Arc<Module>,
}

impl Serializer for ContractVersion {
    fn write(&self, writer: &mut Writer) {
        writer.write_u8(*self as u8);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        match reader.read_u8()? {
            0 => Ok(ContractVersion::V1),
            _ => Err(ReaderError::InvalidValue),
        }
    }

    fn size(&self) -> usize {
        1
    }
}

impl Serializer for ContractModule {
    fn write(&self, writer: &mut Writer) {
        self.version.write(writer);
        self.module.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let version = ContractVersion::read(reader)?;
        let module = Module::read(reader)?;

        Ok(Self {
            version,
            module: Arc::new(module),
        })
    }

    fn size(&self) -> usize {
        self.version.size() + self.module.size()
    }
}