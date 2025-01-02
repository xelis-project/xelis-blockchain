use std::{fmt::{Display, Formatter, self}, str::FromStr};
use serde::{Serialize, Deserialize};

use crate::serializer::{Serializer, Reader, ReaderError, Writer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Network {
    Mainnet,
    Testnet,
    Dev
}

impl Default for Network {
    fn default() -> Self {
        Self::Mainnet
    }
}

impl Network {
    pub fn is_mainnet(&self) -> bool {
        match &self {
            Self::Mainnet => true,
            _ => false
        }
    }
}

impl Serialize for Network {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for Network {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let str = match &self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Dev => "dev"
        };
        write!(f, "{}", str)
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "mainnet" | "0" => Self::Mainnet,
            "testnet" | "1" => Self::Testnet,
            "dev" | "2" => Self::Dev,
            _ => return Err("Invalid network".into())
        })
    }
}

impl Serializer for Network {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(match reader.read_u8()? {
            0 => Self::Mainnet,
            1 => Self::Testnet,
            2 => Self::Dev,
            _ => return Err(ReaderError::InvalidValue)
        })
    }

    fn write(&self, writer: &mut Writer) {
        let id = match &self {
          Self::Mainnet => 0,
          Self::Testnet => 1,
          Self::Dev => 2 
        };
        writer.write_u8(id);
    }

    fn size(&self) -> usize {
        1
    }
}