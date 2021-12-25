use super::reader::{Reader, ReaderError};

pub trait Serializer {
    fn to_bytes(&self) -> Vec<u8>;

    fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    fn size(&self) -> usize {
        self.to_bytes().len()
    }

    fn from_bytes(reader: &mut Reader) -> Result<Box<Self>, ReaderError>;

    fn from_hex(hex: String) -> Result<Box<Self>, ReaderError> {
        let mut reader = match hex::decode(&hex) {
            Ok(bytes) => Reader::new(bytes),
            Err(_) => return Err(ReaderError::InvalidHex)
        };

        Serializer::from_bytes(&mut reader)
    }
}