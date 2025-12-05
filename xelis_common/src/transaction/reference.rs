use std::fmt;
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};
use crate::{
    crypto::Hash,
    block::TopoHeight,
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
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
    fn write(&self, writer: &mut Writer) {
        self.hash.write(writer);
        self.topoheight.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Reference, ReaderError> {
        let hash = Hash::read(reader)?;
        let topoheight = Reader::read(reader)?;
        Ok(Reference {
            hash,
            topoheight
        })
    }

    fn size(&self) -> usize {
        self.hash.size() + self.topoheight.size()
    }
}