use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::serializer::*;

/// 32-bytes shared key used to encrypt/decrypt the extra data
#[derive(Debug, Clone, JsonSchema)]
#[schemars(with = "String")]
pub struct SharedKey(pub [u8; 32]);

impl Serializer for SharedKey {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self(reader.read()?))
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl Serialize for SharedKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.to_hex().serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for SharedKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let hex = String::deserialize(deserializer)?;
        SharedKey::from_hex(&hex)
            .map_err(serde::de::Error::custom)
    }
}