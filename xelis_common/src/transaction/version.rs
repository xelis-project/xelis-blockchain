use crate::serializer::{Reader, ReaderError, Serializer, Writer};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxVersion {
    V0,
    V1
}

impl TryFrom<u8> for TxVersion {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TxVersion::V0),
            1 => Ok(TxVersion::V1),
            _ => Err(()),
        }
    }
}

impl Into<u8> for TxVersion {
    fn into(self) -> u8 {
        match self {
            TxVersion::V0 => 0,
            TxVersion::V1 => 1,
        }
    }
}

impl Into<u64> for TxVersion {
    fn into(self) -> u64 {
        let byte: u8 = self.into();
        byte as u64
    }
}

impl Serializer for TxVersion {
    fn write(&self, writer: &mut Writer) {
        match self {
            TxVersion::V0 => writer.write_u8(0),
            TxVersion::V1 => writer.write_u8(1),
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError>
        where Self: Sized {
        let id = reader.read_u8()?;
        Self::try_from(id).map_err(|_| ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        1
    }
}

impl fmt::Display for TxVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TxVersion::V0 => write!(f, "V0"),
            TxVersion::V1 => write!(f, "V1"),
        }
    }
}

impl serde::Serialize for TxVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> serde::Deserialize<'de> for TxVersion {
    fn deserialize<D>(deserializer: D) -> Result<TxVersion, D::Error>
        where D: serde::Deserializer<'de> {
        let value = u8::deserialize(deserializer)?;
        TxVersion::try_from(value).map_err(|_| serde::de::Error::custom("Invalid value for TxVersion"))
    }
}