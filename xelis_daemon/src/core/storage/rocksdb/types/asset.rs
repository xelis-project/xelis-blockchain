use xelis_common::{block::TopoHeight, serializer::*};

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
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let id = AssetId::read(reader)?;
        let data_pointer = Option::read(reader)?;
        let supply_pointer = Option::read(reader)?;

        Ok(Self {
            id,
            data_pointer,
            supply_pointer
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.id.write(writer);
        self.data_pointer.write(writer);
        self.supply_pointer.write(writer);
    }

    fn size(&self) -> usize {
        self.id.size()
        + self.data_pointer.size()
        + self.supply_pointer.size()
    }
}