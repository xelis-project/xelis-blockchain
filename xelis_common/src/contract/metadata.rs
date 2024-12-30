use xelis_vm::Module;

use crate::serializer::*;

#[derive(Debug)]
pub struct ContractMetadata {
    pub module: Module
}

impl Serializer for ContractMetadata {
    fn write(&self, writer: &mut Writer) {
        self.module.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let module = Module::read(reader)?;
        Ok(Self { module })
    }

    fn size(&self) -> usize {
        self.module.size()
    }
}