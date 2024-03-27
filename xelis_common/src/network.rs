use std::{fmt::{Display, Formatter, self}, str::FromStr};
use serde::{Serialize, Deserialize};

use crate::serializer::{Serializer, Reader, ReaderError, Writer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Network {
    Mainnet,
    Testnet,
    Dev
}

impl Network {
    pub fn is_mainnet(&self) -> bool {
        match &self {
            Self::Mainnet => true,
            _ => false
        }
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let str = match &self {
            Self::Mainnet => "Mainnet",
            Self::Testnet => "Testnet",
            Self::Dev => "Dev"
        };
        write!(f, "{}", str)
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
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