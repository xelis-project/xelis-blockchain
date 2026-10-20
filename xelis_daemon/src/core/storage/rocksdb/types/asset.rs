use xelis_common::{
    block::TopoHeight,
    serializer::{Error as SerializationError, *},
};

pub type AssetId = u64;

pub struct Asset {
    // id used to prevent duplicated raw key
    // and save some space
    pub id: AssetId,
    // pointer to the last VersionedAssetData
    pub data_pointer: Option<TopoHeight>,
    // pointer to the last versioned supply
    pub supply_pointer: Option<TopoHeight>,
}

impl Serializer for Asset {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let id = AssetId::read(reader)?;
            let data_pointer = Option::read(reader)?;
            let supply_pointer = Option::read(reader)?;

            Ok(Self {
                id,
                data_pointer,
                supply_pointer
            })
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.id.write(writer)?;
            self.data_pointer.write(writer)?;
            self.supply_pointer.write(writer)
        })
    }

    fn size(&self) -> usize {
        self.id.size()
        + self.data_pointer.size()
        + self.supply_pointer.size()
    }
}