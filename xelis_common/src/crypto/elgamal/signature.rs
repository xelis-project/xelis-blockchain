use serde::{de::Error, Serialize};
use crate::serializer::{Reader, ReaderError, Serializer, Writer};

pub const SIGNATURE_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(Error::custom)?;
        if bytes.len() != SIGNATURE_SIZE {
            return Err(Error::custom(format!(
                "Invalid signature length: expected {}, got {}",
                SIGNATURE_SIZE,
                bytes.len()
            )));
        }

        let mut arr = [0; SIGNATURE_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }
}

impl Serializer for Signature {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(&self.0);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let bytes = reader.read_bytes(SIGNATURE_SIZE)?;
        Ok(Self::from_bytes(bytes))
    }

    fn size(&self) -> usize {
        SIGNATURE_SIZE
    }
}