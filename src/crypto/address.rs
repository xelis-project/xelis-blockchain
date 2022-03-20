use crate::core::serializer::Serializer;
use crate::core::reader::{Reader, ReaderError};
use super::key::PublicKey;

const PAYMENT_ID_SIZE: usize = 8; //8 bytes for paymentID

pub enum AddressType {
    Normal,
    PaymentId([u8; PAYMENT_ID_SIZE]),
}

pub struct Address {
    mainnet: bool,
    addr_type: AddressType,
    pub_key: PublicKey
}

impl Address {
    pub fn get_public_key(&self) -> &PublicKey {
        &self.pub_key
    }
}

impl Serializer for AddressType {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        match self {
            AddressType::Normal => {
                bytes.push(0);
            },
            AddressType::PaymentId(id) => {
                bytes.push(1);
                bytes.extend(id)
            }
        };
        bytes
    }

    fn from_bytes(reader: &mut Reader) -> Result<AddressType, ReaderError> {
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

impl Serializer for Address {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.push(if self.mainnet { 1 } else { 0 });
        bytes.extend(&self.addr_type.to_bytes());
        bytes.extend(&self.pub_key.to_bytes());

        bytes
    }

    fn from_bytes(reader: &mut Reader) -> Result<Address, ReaderError> {
        let mainnet = match reader.read_u8()? {
            0 => false,
            1 => true,
            _ => return Err(ReaderError::InvalidValue)
        };
        let addr_type = AddressType::from_bytes(reader)?;
        let pub_key = PublicKey::from_bytes(reader)?;

        Ok(Address {
            mainnet,
            addr_type,
            pub_key
        })
    }
}