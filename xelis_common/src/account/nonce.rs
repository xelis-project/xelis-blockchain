use std::fmt::{self, Display, Formatter};
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

#[derive(Clone, Serialize, Deserialize)]
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
        self.nonce.write(writer);
        self.previous_topoheight.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let nonce = Nonce::read(reader)?;
        let previous_topoheight = Option::read(reader)?;

        Ok(Self {
            nonce,
            previous_topoheight
        })
    }

    fn size(&self) -> usize {
        self.nonce.size() + if let Some(topoheight) = self.previous_topoheight { topoheight.size() } else { 0 }
    }
}

impl Display for VersionedNonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce[{}, previous: {:?}", self.nonce, self.previous_topoheight)
    }
}