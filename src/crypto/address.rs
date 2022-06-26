use core::fmt;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};

use crate::core::error::BlockchainError;
use crate::core::reader::{Reader, ReaderError};
use crate::core::serializer::Serializer;
use crate::config::PREFIX_ADDRESS;
use crate::core::writer::Writer;
use super::bech32::{Bech32Error, encode, convert_bits, decode};
use super::key::PublicKey;
use serde::de::Error as SerdeError;

const PAYMENT_ID_SIZE: usize = 8; // 8 bytes for paymentID

pub enum AddressType {
    Normal,
    PaymentId([u8; PAYMENT_ID_SIZE]),
    // TODO add custom variables
}

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

    pub fn is_normal(&self) -> bool {
        match self.addr_type {
            AddressType::Normal => true,
            _=> false
        }
    }

    pub fn as_string(&self) -> Result<String, Bech32Error> {
        let bits = convert_bits(&self.to_bytes(), 8, 5, true)?;
        let result = encode(PREFIX_ADDRESS.to_owned(), &bits)?;
        Ok(result)
    }

    pub fn from_string(address: &String) -> Result<Self, BlockchainError> {
        let (hrp, decoded) = decode(address)?;
        if hrp != PREFIX_ADDRESS {
            return Err(BlockchainError::ErrorOnBech32(Bech32Error::InvalidPrefix(hrp)))
        }

        let bits = convert_bits(&decoded, 5, 8, false)?;
        let mut reader = Reader::new(&bits);
        let addr = Address::read(&mut reader)?;
        Ok(addr)
    }
}

impl Serializer for AddressType {
    fn write(&self, writer: &mut Writer) {
        match self {
            AddressType::Normal => {
                writer.write_u8(0);
            },
            AddressType::PaymentId(id) => {
                writer.write_u8(1);
                writer.write_bytes(id);
            }
        };
    }

    fn read(reader: &mut Reader) -> Result<AddressType, ReaderError> {
        let _type = match reader.read_u8()? {
            0 => AddressType::Normal,
            1 => {
                let id: [u8; PAYMENT_ID_SIZE] = reader.read_bytes(PAYMENT_ID_SIZE)?;
                AddressType::PaymentId(id)
            }
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
        let mainnet = match reader.read_u8()? {
            0 => false,
            1 => true,
            _ => return Err(ReaderError::InvalidValue)
        };
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
        serializer.serialize_str(&self.to_hex())
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