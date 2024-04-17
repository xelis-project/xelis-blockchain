use std::{
    fmt::{Display, Formatter},
    mem,
    str::FromStr
};
use crate::{
    api::{DataElement, ValueType, DataValue},
    serializer::{Serializer, Writer, Reader, ReaderError},
    config::{PREFIX_ADDRESS, TESTNET_PREFIX_ADDRESS},
    transaction::EXTRA_DATA_LIMIT_SIZE
};
use super::{
    bech32::{Bech32Error, encode, convert_bits, decode},
    PublicKey
};
use core::fmt;
use log::debug;
use serde::de::Error as SerdeError;
use anyhow::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressType {
    Normal,
    // Data variant allow to integrate data in address for easier communication / data transfered
    // those data are directly integrated in the data part and can be transfered in the transaction directly
    Data(DataElement)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    mainnet: bool,
    addr_type: AddressType,
    key: PublicKey
}

impl Address {
    pub fn new(mainnet: bool, addr_type: AddressType, key: PublicKey) -> Self {
        Self {
            mainnet,
            addr_type,
            key
        }
    }

    // Get the public key from the address
    pub fn get_public_key(&self) -> &PublicKey {
        &self.key
    }

    // Take the public key from the address
    pub fn to_public_key(self) -> PublicKey {
        self.key
    }

    // Get the address type
    pub fn get_type(&self) -> &AddressType {
        &self.addr_type
    }

    // Split the address into its components
    pub fn split(self) -> (PublicKey, AddressType) {
        (self.key, self.addr_type)
    }

    // Change internally the address type to extract the data
    pub fn extract_data_only(&mut self) -> Option<DataElement> {
        let mut addr_type = AddressType::Normal;
        mem::swap(&mut addr_type, &mut self.addr_type);

        match addr_type {
            AddressType::Data(data) => Some(data),
            AddressType::Normal => None
        }
    }

    // Recreate a new address struct without the integrated data
    pub fn extract_data(self) -> (Option<DataElement>, Self) {
        match self.addr_type {
            AddressType::Data(data) => {
                (Some(data), Self::new(self.mainnet, AddressType::Normal, self.key))
            },
            AddressType::Normal => (None, self)
        }
    }

    // Check if the address is a normal address (no data integrated)
    pub fn is_normal(&self) -> bool {
        match self.addr_type {
            AddressType::Normal => true,
            _=> false
        }
    }

    // Check if the address is a mainnet address
    pub fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    // Compress the address to a byte array
    // We don't use Serializer trait to avoid storing mainnet bool
    fn compress(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.key.write(&mut writer);
        self.addr_type.write(&mut writer);
        writer.bytes()
    }

    // Read the address from a byte array
    // Hrp validity isn't checked here, it should be done before calling this function
    fn decompress(bytes: &[u8], hrp: &str) -> Result<Self, ReaderError> {
        let mut reader = Reader::new(bytes);
        let mainnet = hrp == PREFIX_ADDRESS;
        let key = PublicKey::read(&mut reader)?;
        let addr_type = AddressType::read(&mut reader)?;
        Ok(Self::new(mainnet, addr_type, key))
    }

    // Search for a data value in the address
    pub fn get_data(&self, name: String, value_type: ValueType) -> Option<&DataValue> {
        match &self.addr_type {
            AddressType::Normal => None,
            AddressType::Data(data) => data.get_value_by_string_key(name, value_type)
        }
    }

    // Returns the address as a string (human readable format)
    pub fn as_string(&self) -> Result<String, Bech32Error> {
        let bits = convert_bits(&self.compress(), 8, 5, true)?;
        let hrp = if self.is_mainnet() {
            PREFIX_ADDRESS
        } else {
            TESTNET_PREFIX_ADDRESS
        };

        let result = encode(hrp.to_owned(), &bits)?;
        Ok(result)
    }

    // Parse an address from a string (human readable format)
    pub fn from_string(address: &String) -> Result<Self, Error> {
        let (hrp, decoded) = decode(address)?;
        // check that hrp is valid one
        if hrp != PREFIX_ADDRESS && hrp != TESTNET_PREFIX_ADDRESS {
            return Err(Bech32Error::InvalidPrefix(hrp, format!("{} or {}", PREFIX_ADDRESS, TESTNET_PREFIX_ADDRESS)).into())
        }

        let bits = convert_bits(&decoded, 5, 8, false)?;
        let addr = Address::decompress(&bits, hrp.as_str())?;

        // now check that the hrp decoded is the one for the network state
        if (addr.is_mainnet() && hrp != PREFIX_ADDRESS) || (!addr.is_mainnet() && hrp != TESTNET_PREFIX_ADDRESS) {
            let expected = if addr.is_mainnet() {
                PREFIX_ADDRESS
            } else {
                TESTNET_PREFIX_ADDRESS
            };
            return Err(Bech32Error::InvalidPrefix(hrp, expected.to_owned()).into())
        }

        Ok(addr)
    }
}

impl FromStr for Address {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_string(&s.to_owned())
    }
}

impl Into<PublicKey> for Address {
    fn into(self) -> PublicKey {
        self.to_public_key()
    }
}

impl Into<AddressType> for Address {
    fn into(self) -> AddressType {
        self.addr_type
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
            1 => {
                let read = reader.total_read();
                let addr_type = AddressType::Data(DataElement::read(reader)?);
                if reader.total_read() - read > EXTRA_DATA_LIMIT_SIZE {
                    debug!("Invalid data in integrated address, maximum size reached");
                    return Err(ReaderError::InvalidSize)
                }

                addr_type
            },
            _ => return Err(ReaderError::InvalidValue)
        };
        Ok(_type)
    }

    fn size(&self) -> usize {
        match self {
            AddressType::Normal => 1,
            AddressType::Data(data) => 1 + data.size()
        }
    }
}

impl serde::Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> serde::Deserialize<'a> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'a> {
        let hex = String::deserialize(deserializer)?;
        Address::from_string(&hex).map_err(SerdeError::custom)
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string().map_err(|_| fmt::Error)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;

    use super::{Address, AddressType};

    #[test]
    fn test_serde() {
        let (pub_key, _) = KeyPair::new().split();
        let addr = Address::new(false, AddressType::Normal, pub_key.compress());
        let v = addr.to_string();
        let addr2: Address = Address::from_string(&v).unwrap();
        assert_eq!(addr, addr2);
    }
}