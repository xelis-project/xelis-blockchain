use std::fmt::{self, Display, Formatter};
use serde::{Deserialize, Serialize};
use crate::serializer::{
    Reader,
    ReaderError,
    Serializer,
    Writer
};


#[derive(Clone, Serialize, Deserialize)]
pub struct VersionedNonce {
    nonce: u64,
    previous_topoheight: Option<u64>,
}

impl VersionedNonce {
    pub fn new(nonce: u64, previous_topoheight: Option<u64>) -> Self {
        Self {
            nonce,
            previous_topoheight
        }
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn set_nonce(&mut self, value: u64) {
        self.nonce = value;
    }

    pub fn get_previous_topoheight(&self) -> Option<u64> {
        self.previous_topoheight        
    }

    pub fn set_previous_topoheight(&mut self, previous_topoheight: Option<u64>) {
        self.previous_topoheight = previous_topoheight;
    }
}

impl Serializer for VersionedNonce {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.nonce);
        if let Some(topo) = &self.previous_topoheight {
            writer.write_u64(topo);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let nonce = reader.read_u64()?;
        let previous_topoheight = if reader.size() == 0 {
            None
        } else {
            Some(reader.read_u64()?)
        };

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