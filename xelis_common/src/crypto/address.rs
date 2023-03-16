use core::fmt;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};

use crate::api::DataType;
use crate::serializer::{Serializer, Writer, Reader, ReaderError};
use crate::config::{PREFIX_ADDRESS, TESTNET_PREFIX_ADDRESS};
use super::bech32::{Bech32Error, encode, convert_bits, decode};
use super::key::PublicKey;
use serde::de::Error as SerdeError;
use anyhow::Error;

#[derive(Clone)]
pub enum AddressType {
    Normal,
    // Data variant allow to integrate data in address for easier communication / data transfered
    // those data are directly integrated in the data part and can be transfered in the transaction directly
    Data(DataType)
}

#[derive(Clone)]
pub struct Address<'a> {
    mainnet: bool,
    addr_type: AddressType,
    pub_key: Cow<'a, PublicKey>
}

impl<'a> Address<'a> {
    pub fn new(mainnet: bool, addr_type: AddressType, pub_key: Cow<'a, PublicKey>) -> Self {
        Self {
            mainnet,
            addr_type,
            pub_key
        }
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.pub_key
    }

    pub fn to_public_key(self) -> PublicKey {
        self.pub_key.into_owned()
    }

    pub fn get_type(&self) -> &AddressType {
        &self.addr_type
    }

    pub fn split(self) -> (PublicKey, AddressType) {
        (self.pub_key.into_owned(), self.addr_type)
    }

    pub fn is_normal(&self) -> bool {
        match self.addr_type {
            AddressType::Normal => true,
            _=> false
        }
    }

    pub fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    pub fn as_string(&self) -> Result<String, Bech32Error> {
        let bits = convert_bits(&self.to_bytes(), 8, 5, true)?;
        let hrp = if self.is_mainnet() {
            PREFIX_ADDRESS
        } else {
            TESTNET_PREFIX_ADDRESS
        };

        let result = encode(hrp.to_owned(), &bits)?;
        Ok(result)
    }

    pub fn from_string(address: &String) -> Result<Self, Error> {
        let (hrp, decoded) = decode(address)?;
        // check that hrp is valid one
        if hrp != PREFIX_ADDRESS || hrp != TESTNET_PREFIX_ADDRESS {
            return Err(Bech32Error::InvalidPrefix(hrp).into())
        }

        let bits = convert_bits(&decoded, 5, 8, false)?;
        let mut reader = Reader::new(&bits);
        let addr = Address::read(&mut reader)?;

        // now check that the hrp decoded is the one for the network state
        if (addr.is_mainnet() && hrp != PREFIX_ADDRESS) || (!addr.is_mainnet() && hrp != TESTNET_PREFIX_ADDRESS) {
            return Err(Bech32Error::InvalidPrefix(hrp).into())
        }

        Ok(addr)
    }
}

impl Serializer for AddressType {
    fn write(&self, writer: &mut Writer) {
        match self {
            AddressType::Normal => {
                writer.write_u8(0);
            },
            AddressType::Data(data) => {
                writer.write_u8(1);
                data.write(writer);
            }
        };
    }

    fn read(reader: &mut Reader) -> Result<AddressType, ReaderError> {
        let _type = match reader.read_u8()? {
            0 => AddressType::Normal,
            1 => AddressType::Data(DataType::read(reader)?),
            _ => return Err(ReaderError::InvalidValue)
        };
        Ok(_type)
    }
}

impl<'a> Serializer for Address<'a> {
    fn write(&self, writer: &mut Writer) {
        writer.write_bool(&self.mainnet);
        self.addr_type.write(writer);
        self.pub_key.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Address<'a>, ReaderError> {
        let mainnet = reader.read_bool()?;
        let addr_type = AddressType::read(reader)?;
        let pub_key = PublicKey::read(reader)?;

        Ok(Address {
            mainnet,
            addr_type,
            pub_key: Cow::Owned(pub_key)
        })
    }
}

impl serde::Serialize for Address<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> serde::Deserialize<'a> for Address<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'a> {
        let hex = String::deserialize(deserializer)?;
        Address::from_string(&hex).map_err(|e| SerdeError::custom(e))
    }
}

impl Display for Address<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string().unwrap())
    }
}