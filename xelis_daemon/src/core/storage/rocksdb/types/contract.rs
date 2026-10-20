use xelis_common::{
    block::TopoHeight,
    serializer::{Error as SerializationError, *},
};

pub type ContractId = u64;
pub type ContractDataId = u64;

pub struct Contract {
    pub id: ContractId,
    pub module_pointer: Option<TopoHeight>,
}

impl Serializer for Contract {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.id.write(writer)?;
            self.module_pointer.write(writer)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let id = ContractId::read(reader)?;
            let module_pointer = Option::read(reader)?;

            Ok(Self {
                id,
                module_pointer
            })
        })
    }
}