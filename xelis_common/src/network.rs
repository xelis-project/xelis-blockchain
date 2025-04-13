use std::{fmt::{Display, Formatter, self}, str::FromStr};
use serde::{Serialize, Deserialize};

use crate::serializer::{Serializer, Reader, ReaderError, Writer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Dev
}

#[cfg(feature = "clap")]
impl clap::ValueEnum for Network {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Mainnet, Self::Testnet, Self::Dev]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Self::Mainnet => Some(clap::builder::PossibleValue::new("mainnet").alias("Mainnet")),
            Self::Testnet => Some(clap::builder::PossibleValue::new("testnet").alias("Testnet")),
            Self::Dev => Some(clap::builder::PossibleValue::new("dev").alias("Dev"))
        }
    }

    fn from_str(input: &str, _: bool) -> Result<Self, String> {
        input.parse().map_err(|_| format!("Invalid network: {}", input))
    }
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