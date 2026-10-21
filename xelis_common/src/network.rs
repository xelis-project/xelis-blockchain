use crate::serializer::{
    DecodeError,
    Error as SerializationError,
    Readable,
    Reader,
    ReaderError,
    Serializer,
    Writable,
    Writer,
};
use std::{fmt::{Display, Formatter, self}, str::FromStr};
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
pub enum Network {
    // Production network
    // This is the main network where real transactions happen
    Mainnet,
    // Test network
    // This is a stable environment for testing purposes
    Testnet,
    // Stage network
    // This is a development network for testing (unstable) new features
    Stagenet,
    // Development network
    // This is a local network for development purposes
    Devnet
}

#[cfg(feature = "clap")]
impl clap::ValueEnum for Network {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Mainnet, Self::Testnet, Self::Stagenet, Self::Devnet]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Self::Mainnet => Some(clap::builder::PossibleValue::new("mainnet").alias("Mainnet")),
            Self::Testnet => Some(clap::builder::PossibleValue::new("testnet").alias("Testnet")),
            Self::Stagenet => Some(clap::builder::PossibleValue::new("stagenet").alias("Stagenet")),
            Self::Devnet => Some(clap::builder::PossibleValue::new("devnet").alias("Devnet"))
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
        serializer.serialize_str(self.to_string().to_lowercase().as_str())
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
            Self::Stagenet => "Stagenet",
            Self::Devnet => "Devnet"
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
            "stagenet" | "2" => Self::Stagenet,
            "devnet" | "3" => Self::Devnet,
            _ => return Err("Invalid network".into())
        })
    }
}

impl Serializer for Network {
    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(match u8::read(reader)? {
                0 => Self::Mainnet,
                1 => Self::Testnet,
                2 => Self::Stagenet,
                3 => Self::Devnet,
                tag => return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown network tag {tag}")))
            })
        })
    }

    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            let id: u8 = match &self {
                Self::Mainnet => 0,
                Self::Testnet => 1,
                Self::Stagenet => 2,
                Self::Devnet => 3 
            };
            id.write(writer)
        })
    }

    fn size(&self) -> usize {
        1
    }
}