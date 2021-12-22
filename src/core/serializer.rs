use super::reader::{Reader, ReaderError};


pub trait Serializer {
    fn to_bytes(&self) -> Vec<u8>;

    fn size(&self) -> usize {
        self.to_bytes().len()
    }

    fn from_bytes(reader: &mut Reader) -> Result<Box<Self>, ReaderError>;
}