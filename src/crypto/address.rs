use super::key::PublicKey;
use crate::core::serializer::Serializer;

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

    fn from_bytes(buf: &[u8]) -> Option<(Box<AddressType>, usize)> {
        None // TODO
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

    fn from_bytes(buf: &[u8]) -> Option<(Box<Address>, usize)> {
        None // TODO
    }
}