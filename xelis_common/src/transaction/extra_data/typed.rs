use crate::{
    api::DataElement,
    serializer::{Reader, ReaderError, Serializer, Writer}
};
use super::{ExtraData, PlaintextData};


// Versioned extra data
pub enum ExtraDataType {
    // Default mode
    // Generate a shared key and encrypt the payload
    Private(ExtraData),
    // Public version will just
    // store it as is
    Public(PlaintextData),
    // Can be anything
    Proprietary(Vec<u8>)
}

impl ExtraDataType {
    // Estimate the final size for the extra data based on the plaintext format
    pub fn estimate_size(data: &DataElement, private: bool) -> usize {
        if private {
            ExtraData::estimate_size(data) + 1
        } else {
            // 1 byte for type variant
            // 2 bytes for inner data len
            // 2 bytes for unknown data format len
            1 + 2 + 2 + data.size()
        }
    }
}

impl Serializer for ExtraDataType {
    fn write(&self, writer: &mut Writer) {
        match self {
            Self::Private(payload) => {
                writer.write_u8(0);
                payload.write(writer);
            },
            Self::Public(payload) => {
                writer.write_u8(1);
                payload.0.write(writer);
            },
            Self::Proprietary(payload) => {
                writer.write_u8(2);
                payload.write(writer);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => Self::Private(ExtraData::read(reader)?),
            1 => Self::Public(PlaintextData(Vec::read(reader)?)),
            2 => Self::Proprietary(Vec::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        })
    }
}
