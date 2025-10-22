use std::fmt::{self, Display, Formatter};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::{
    block::TopoHeight,
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};

pub type Nonce = u64;

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct VersionedNonce {
    nonce: Nonce,
    previous_topoheight: Option<TopoHeight>,
}

impl VersionedNonce {
    pub fn new(nonce: Nonce, previous_topoheight: Option<TopoHeight>) -> Self {
        Self {
            nonce,
            previous_topoheight
        }
    }

    pub fn get_nonce(&self) -> Nonce {
        self.nonce
    }

    pub fn set_nonce(&mut self, value: Nonce) {
        self.nonce = value;
    }

    pub fn get_previous_topoheight(&self) -> Option<TopoHeight> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<TopoHeight>) {
        self.previous_topoheight = previous_topoheight;
    }
}

impl Serializer for VersionedNonce {
    fn write(&self, writer: &mut Writer) {
        self.previous_topoheight.write(writer);
        self.nonce.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let previous_topoheight = Option::read(reader)?;
        let nonce = Nonce::read(reader)?;

        Ok(Self {
            nonce,
            previous_topoheight
        })
    }

    fn size(&self) -> usize {
        self.nonce.size() + self.previous_topoheight.size()
    }
}

impl Display for VersionedNonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce[{}, previous: {:?}", self.nonce, self.previous_topoheight)
    }
}