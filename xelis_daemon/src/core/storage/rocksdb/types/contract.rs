use xelis_common::{block::TopoHeight, serializer::*};

pub type ContractId = u64;

pub struct Contract {
    pub id: ContractId,
    pub module_pointer: Option<TopoHeight>,
}

impl Serializer for Contract {
    fn write(&self, writer: &mut Writer) {
        self.id.write(writer);
        self.module_pointer.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = ContractId::read(reader)?;
        let module_pointer = Option::read(reader)?;

        Ok(Self {
            id,
            module_pointer
        })
    }
}