use super::key::PublicKey;

pub enum AddressType {
    Normal,
    PaymentId([u8; 8]), //8 bytes for paymentID
}

pub struct Address {
    mainnet: bool,
    addr_type: AddressType,
    pub_key: PublicKey
}