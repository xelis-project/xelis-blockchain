mod defaults;
mod reader;
mod writer;

pub use reader::{Reader, ReaderError};
pub use writer::Writer;
use std::marker::Sized;

pub trait Serializer {
    fn write(&self, writer: &mut Writer);

    fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write(&mut writer);
        writer.bytes()
    }

    fn to_hex(&self) -> String {
        let mut writer = Writer::new();
        self.write(&mut writer);
        hex::encode(writer.bytes())
    }

    fn size(&self) -> usize {
        let mut writer = Writer::new();
        self.write(&mut writer);
        writer.total_write()
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError>
    where Self: Sized;

    fn from_hex(hex: String) -> Result<Self, ReaderError>
    where Self: Sized {
        match hex::decode(&hex) {
            Ok(bytes) => {
                let mut reader = Reader::new(&bytes);
                Self::read(&mut reader)
            },
            Err(_) => Err(ReaderError::InvalidHex)
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ReaderError>
    where Self: Sized {
        let mut reader = Reader::new(bytes);
        Self::read(&mut reader)
    }
}