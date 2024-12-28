use crate::{
    serializer::{Reader, ReaderError, Serializer, Writer},
    transaction::TxVersion
};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BlockVersion {
    // Genesis version
    V0,
    // First hard fork including the new PoW algorithm
    // difficulty adjustment algorithm tweaks
    V1,
    // MultiSig, P2P
    V2,
    // Smart Contracts
    V3,
}

impl BlockVersion {
    // Check if a transaction version is allowed in a block version
    pub fn is_tx_version_allowed(&self, tx_version: TxVersion) -> bool {
        match self {
            BlockVersion::V0 | BlockVersion::V1 => matches!(tx_version, TxVersion::V0),
            BlockVersion::V2 => matches!(tx_version, TxVersion::V0 | TxVersion::V1),
            BlockVersion::V3 => matches!(tx_version, TxVersion::V0 | TxVersion::V1 | TxVersion::V2),
        }
    }

    // Get the transaction version for a given block version
    pub fn get_tx_version(&self) -> TxVersion {
        match self {
            BlockVersion::V0 | BlockVersion::V1 => TxVersion::V0,
            BlockVersion::V2 => TxVersion::V1,
            BlockVersion::V3 => TxVersion::V2,
        }
    }
}

impl TryFrom<u8> for BlockVersion {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BlockVersion::V0),
            1 => Ok(BlockVersion::V1),
            2 => Ok(BlockVersion::V2),
            3 => Ok(BlockVersion::V3),
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
            BlockVersion::V3 => writer.write_u8(3),
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
            BlockVersion::V3 => write!(f, "V3"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_version_serde() {
        let version = BlockVersion::V0;
        let serialized = serde_json::to_string(&version).unwrap();
        assert_eq!(serialized, "0");

        let deserialized: BlockVersion = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, version);
    }

    #[test]
    fn test_block_version_ord() {
        assert!(BlockVersion::V0 < BlockVersion::V1);
        assert!(BlockVersion::V1 < BlockVersion::V2);
    }
}