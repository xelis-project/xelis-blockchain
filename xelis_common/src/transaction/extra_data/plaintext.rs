use serde::{Deserialize, Serialize};

use crate::{
    api::DataElement,
    serializer::*,
};
use super::SharedKey;

/// Extra data stored in plaintext
/// We store its shared key next to the data for future usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaintextExtraData {
    /// Shared key used to encrypt/decrypt the data
    shared_key: Option<SharedKey>,
    /// Data stored in the extra data
    data: DataElement,
}

impl PlaintextExtraData {
    pub fn new(shared_key: Option<SharedKey>, data: DataElement) -> Self {
        Self {
            shared_key,
            data,
        }
    }

    pub fn shared_key(&self) -> Option<&SharedKey> {
        self.shared_key.as_ref()
    }

    pub fn data(&self) -> &DataElement {
        &self.data
    }
}

impl Serializer for PlaintextExtraData {
    fn write(&self, writer: &mut Writer) {
        self.shared_key.write(writer);
        self.data.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self {
            shared_key: Option::read(reader)?,
            data: DataElement::read(reader)?,
        })
    }
}