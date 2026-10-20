use crate::serializer::{Error as SerializationError, *};
use schemars::JsonSchema;
use serde::{
    de::Error as DeserializeError,
    ser::Error as SerializeError,
    Deserialize,
    Deserializer,
    Serialize,
    Serializer as SerdeSerializer,
};

/// 32-bytes shared key used to encrypt/decrypt the extra data
#[derive(Debug, Clone, JsonSchema)]
#[schemars(with = "String")]
pub struct SharedKey(pub [u8; 32]);

impl Serializer for SharedKey {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| self.0.write(writer))
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(Self(reader.read()?))
        })
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl Serialize for SharedKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: SerdeSerializer,
    {
        self.0.to_hex().map_err(SerializeError::custom)?.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for SharedKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        let hex = String::deserialize(deserializer)?;
        SharedKey::from_hex(&hex)
            .map_err(DeserializeError::custom)
    }
}