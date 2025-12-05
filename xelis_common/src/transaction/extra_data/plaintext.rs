use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    api::DataElement,
    serializer::*,
};
use super::SharedKey;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextFlag {
    // Extra data come from an encrypted payload
    // we decrypted it successfully
    Private,
    // Extra data was public on chain
    // We decoded it successfully
    Public,
    // Payload is using a proprietary encoding
    // We store it as is in a ValueType::Blob
    Proprietary,
    // Decoding has failed, we don't store any
    Failed
}

impl Serializer for PlaintextFlag {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        match reader.read_u8()? {
            0 => Ok(Self::Private),
            1 => Ok(Self::Public),
            2 => Ok(Self::Proprietary),
            3 => Ok(Self::Failed),
            _ => Err(ReaderError::InvalidValue)
        }
    }

    fn write(&self, writer: &mut Writer) {
        let id = match self {
            Self::Private => 0,
            Self::Public => 1,
            Self::Proprietary => 2,
            Self::Failed => 3
        };
        writer.write_u8(id);
    }

    fn size(&self) -> usize {
        1
    }
}

/// Extra data stored in plaintext
/// We store its shared key next to the data for future usage
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlaintextExtraData {
    /// Shared key used to encrypt/decrypt the data
    shared_key: Option<SharedKey>,
    /// Data stored in the extra data
    data: Option<DataElement>,
    // Plaintext flag including its type
    flag: PlaintextFlag,
}

impl PlaintextExtraData {
    pub fn new(shared_key: Option<SharedKey>, data: Option<DataElement>, flag: PlaintextFlag) -> Self {
        Self {
            shared_key,
            data,
            flag
        }
    }

    pub fn shared_key(&self) -> Option<&SharedKey> {
        self.shared_key.as_ref()
    }

    pub fn data(&self) -> Option<&DataElement> {
        self.data.as_ref()
    }

    pub fn flag(&self) -> PlaintextFlag {
        self.flag
    }
}

impl Serializer for PlaintextExtraData {
    fn write(&self, writer: &mut Writer) {
        self.shared_key.write(writer);
        self.data.write(writer);
        self.flag.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self {
            shared_key: Option::read(reader)?,
            data: Option::read(reader)?,
            flag: PlaintextFlag::read(reader)?
        })
    }

    fn size(&self) -> usize {
        self.shared_key.size()
        + self.data.size()
        + self.flag.size()
    }
}