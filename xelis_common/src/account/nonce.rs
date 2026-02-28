use std::fmt::{self, Display, Formatter};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::{
    block::TopoHeight,
    versioned::TopoHeightVersioned,
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};
/// Nonce is a u64 that represents the number of transactions sent by an account
/// It is used to prevent replay attacks and to order transactions from the same account
pub type Nonce = u64;

/// VersionedNonce is a versioned type that represents the nonce of an account at a specific topoheight
/// It is used to store the nonce of an account at different topoheights, so we can retrieve the nonce at a specific topoheight
/// or the last nonce of an account
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

impl TopoHeightVersioned for VersionedNonce {
    fn get_previous(&self) -> Option<TopoHeight> {
        self.get_previous_topoheight()
    }

    fn set_previous(&mut self, previous: Option<TopoHeight>) {
        self.set_previous_topoheight(previous);
    }
}