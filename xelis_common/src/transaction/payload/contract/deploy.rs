use serde::{Deserialize, Serialize};
use xelis_vm::Module;

use crate::serializer::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeployContractPayload {
    pub module: Module
}

impl Serializer for DeployContractPayload {
    fn write(&self, writer: &mut Writer) {
        self.module.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> { 
        Ok(Self {
            module: Module::read(reader)?
        })
    }

    fn size(&self) -> usize {
        self.module.size()
    }
}