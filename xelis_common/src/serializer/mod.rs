mod defaults;
mod reader;
mod writer;
mod hexable;
mod raw;
mod count;
mod dynamic_len;

use std::marker::Sized;

pub use reader::*;
pub use writer::Writer;
pub use defaults::DEFAULT_MAX_ITEMS;
pub use hexable::*;
pub use raw::*;
pub use count::*;
pub use dynamic_len::*;

pub trait Serializer {
    fn write(&self, writer: &mut Writer);

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut writer = Writer::new(&mut buffer);
        self.write(&mut writer);
        buffer
    }

    fn to_hex(&self) -> String {
        let mut buffer = Vec::new();
        let mut writer = Writer::new(&mut buffer);
        self.write(&mut writer);
        hex::encode(buffer)
    }

    fn size(&self) -> usize {
        let mut buffer = Vec::new();
        let mut writer = Writer::new(&mut buffer);
        self.write(&mut writer);
        buffer.len()
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError>
    where Self: Sized;

    fn from_hex(hex: &str) -> Result<Self, ReaderError>
    where Self: Sized {
        match hex::decode(hex) {
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