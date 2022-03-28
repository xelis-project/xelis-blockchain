use crate::core::serializer::Serializer;
use crate::core::reader::{Reader, ReaderError};
use crate::core::writer::Writer;
use super::key::PublicKey;

const PAYMENT_ID_SIZE: usize = 8; // 8 bytes for paymentID

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

impl Serializer for Address {
    fn write(&self, writer: &mut Writer) {
        writer.write_bool(&self.mainnet);
        self.addr_type.write(writer);
        self.pub_key.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Address, ReaderError> {
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
            pub_key
        })
    }
}