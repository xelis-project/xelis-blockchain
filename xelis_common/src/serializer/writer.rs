use crate::crypto::Hash;
use super::{Error, Writable, Writer};

/// XELIS encodings on an octet writer. Lengths retain their protocol encoding.
pub trait WriterExt {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error>;

    fn write_hash(&mut self, hash: &Hash) -> Result<(), Error> {
        self.write_bytes(hash.as_bytes())
    }

    fn write_bool(&mut self, value: bool) -> Result<(), Error> {
        self.write_u8(u8::from(value))
    }

    fn write_u8(&mut self, value: u8) -> Result<(), Error> {
        self.write_bytes(&[value])
    }

    fn write_u16(&mut self, value: u16) -> Result<(), Error> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), Error> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_u64(&mut self, value: u64) -> Result<(), Error> {
        self.write_bytes(&value.to_be_bytes())
    }

    fn write_u128(&mut self, value: u128) -> Result<(), Error> {
        self.write_bytes(&value.to_be_bytes())
    }

    // Preserve the one-byte length and the existing 255-byte payload limit.
    fn write_string(&mut self, value: &str) -> Result<(), Error> {
        let bytes = value.as_bytes();
        self.write_u8(bytes.len() as u8)?;
        self.write_bytes(&bytes[..bytes.len().min(u8::MAX as usize)])
    }

    fn write_optional_string(&mut self, value: &Option<String>) -> Result<(), Error> {
        match value {
            Some(value) => self.write_string(value),
            None => self.write_u8(0),
        }
    }

    fn write_optional_non_zero_u8(&mut self, value: Option<u8>) -> Result<(), Error> {
        self.write_u8(value.unwrap_or(0))
    }

    fn write_optional_non_zero_u16(&mut self, value: Option<u16>) -> Result<(), Error> {
        self.write_u16(value.unwrap_or(0))
    }

    fn write_optional_non_zero_u64(&mut self, value: Option<u64>) -> Result<(), Error> {
        self.write_u64(value.unwrap_or(0))
    }
}

impl<'ty, 'r, W: Writable> WriterExt for Writer<'ty, 'r, W> {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.extend_bytes(bytes)
    }
}
