use crate::{
    api::DataElement,
    serializer::{
        DecodeError,
        Error as SerializationError,
        Readable,
        Reader,
        ReaderError,
        Serializer,
        Writable,
        Writer,
    },
};
use super::{ExtraData, PlaintextData};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum ExtraDataKind {
    Private,
    Public,
    Proprietary
}

impl TryFrom<u8> for ExtraDataKind {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Private,
            1 => Self::Public,
            2 => Self::Proprietary,
            _ => return Err("Invalid value")
        })
    }
}

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

    pub fn kind(&self) -> ExtraDataKind {
        match self {
            Self::Private(_) => ExtraDataKind::Private,
            Self::Public(_) => ExtraDataKind::Public,
            Self::Proprietary(_) => ExtraDataKind::Proprietary
        }
    }
}

impl Serializer for ExtraDataType {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            match self {
                Self::Private(payload) => {
                    0u8.write(writer)?;
                    payload.write(writer)
                },
                Self::Public(payload) => {
                    1u8.write(writer)?;
                    payload.0.write(writer)
                },
                Self::Proprietary(payload) => {
                    2u8.write(writer)?;
                    payload.write(writer)
                }
            }
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(match u8::read(reader)? {
                0 => Self::Private(ExtraData::read(reader)?),
                1 => Self::Public(PlaintextData(Vec::read(reader)?)),
                2 => {
                    // We read manually to prevent the max default items limit
                    let len = u16::read(reader)?;
                    let values = reader.read_vec(len as usize)?;
                    Self::Proprietary(values)
                },
                tag => return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown extra data kind tag {tag}")))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serializer::Serializer;

    #[test]
    fn test_proprietary() {
        let inner = vec![0; 2048];
        let v = ExtraDataType::Proprietary(inner.clone());
        let bytes = v.to_bytes().unwrap();
        let v2 = ExtraDataType::from_bytes(&bytes).unwrap();
        assert!(matches!(v2.kind(), ExtraDataKind::Proprietary));
        let ExtraDataType::Proprietary(v2) = v2 else {
            panic!("invalid variant");
        };

        assert!(inner == v2);
    }
}