use std::fmt;
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};
use crate::{
    crypto::Hash,
    block::TopoHeight,
    serializer::{
        Error as SerializationError,
        Readable,
        Reader,
        ReaderError,
        ReaderExt,
        Serializer,
        Writable,
        Writer,
    },
};

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct Reference {
    pub hash: Hash,
    pub topoheight: TopoHeight,
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reference[hash: {}, topoheight: {}]", self.hash, self.topoheight)
    }
}

impl PartialEq for Reference {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.topoheight == other.topoheight
    }
}

impl Serializer for Reference {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.hash.write(writer)?;
            self.topoheight.write(writer)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Reference, ReaderError> {
        reader.read_with_context(|reader| {
            let hash = Hash::read(reader)?;
            let topoheight = reader.read()?;
            Ok(Reference {
                hash,
                topoheight
            })
        })
    }

    fn size(&self) -> usize {
        self.hash.size() + self.topoheight.size()
    }
}