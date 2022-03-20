use super::reader::{Reader, ReaderError};
use std::marker::Sized;

pub trait Serializer {
    fn to_bytes(&self) -> Vec<u8>;

    fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    fn size(&self) -> usize {
        self.to_bytes().len()
    }

    fn from_bytes(reader: &mut Reader) -> Result<Self, ReaderError>
    where Self: Sized;

    fn from_hex(hex: String) -> Result<Self, ReaderError>
    where Self: Sized {
        match hex::decode(&hex) {
            Ok(bytes) => {
                let mut reader = Reader::new(&bytes);
                Serializer::from_bytes(&mut reader)
            },
            Err(_) => Err(ReaderError::InvalidHex)
        }
    }
}