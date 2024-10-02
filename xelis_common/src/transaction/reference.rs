use std::fmt;
use serde::{Serialize, Deserialize};
use crate::{crypto::Hash, serializer::{Reader, ReaderError, Serializer, Writer}};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Reference {
    pub hash: Hash,
    pub topoheight: u64,
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
        writer.write_u64(&self.topoheight);
    }

    fn read(reader: &mut Reader) -> Result<Reference, ReaderError> {
        let hash = Hash::read(reader)?;
        let topoheight = reader.read_u64()?;
        Ok(Reference {
            hash,
            topoheight
        })
    }

    fn size(&self) -> usize {
        self.hash.size() + self.topoheight.size()
    }
}