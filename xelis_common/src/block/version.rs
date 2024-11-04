use crate::serializer::{Reader, ReaderError, Serializer, Writer};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockVersion {
    // Genesis version
    V0,
    // First hard fork including the new PoW algorithm
    // difficulty adjustment algorithm tweaks
    V1,
    // Smart Contracts, MultiSig, P2p, etc
    V2,
}

impl TryFrom<u8> for BlockVersion {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BlockVersion::V0),
            1 => Ok(BlockVersion::V1),
            2 => Ok(BlockVersion::V2),
            _ => Err(()),
        }
    }
}

impl Serializer for BlockVersion {
    fn write(&self, writer: &mut Writer) {
        match self {
            BlockVersion::V0 => writer.write_u8(0),
            BlockVersion::V1 => writer.write_u8(1),
            BlockVersion::V2 => writer.write_u8(2),
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

impl fmt::Display for BlockVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BlockVersion::V0 => write!(f, "V0"),
            BlockVersion::V1 => write!(f, "V1"),
            BlockVersion::V2 => write!(f, "V2"),
        }
    }
}

impl serde::Serialize for BlockVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> serde::Deserialize<'de> for BlockVersion {
    fn deserialize<D>(deserializer: D) -> Result<BlockVersion, D::Error>
        where D: serde::Deserializer<'de> {
        let value = u8::deserialize(deserializer)?;
        BlockVersion::try_from(value).map_err(|_| serde::de::Error::custom("Invalid value for BlockVersion"))
    }
}