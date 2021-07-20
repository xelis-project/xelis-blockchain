use super::key::PublicKey;
use super::hash::Hashable;

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

impl Hashable for AddressType {
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
}

impl Hashable for Address {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.push(if self.mainnet { 1 } else { 0 });
        bytes.extend(&self.addr_type.to_bytes());
        bytes.extend(&self.pub_key.to_bytes());

        bytes
    }
}