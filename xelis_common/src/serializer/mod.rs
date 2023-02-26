pub mod defaults;

use crate::crypto::hash::Hash;
use std::fmt::{Display, Error, Formatter};
use std::convert::TryInto;
use num_bigint::BigUint;
use std::marker::Sized;
use thiserror::Error;

pub struct Writer {
    bytes: Vec<u8>
}

impl Writer {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new()
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes);
    }

    pub fn write_hash(&mut self, hash: &Hash) {
        self.bytes.extend(hash.as_bytes())
    }

    pub fn write_bool(&mut self, value: &bool) {
        self.bytes.push(if *value { 1 } else { 0 });
    }
    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u16(&mut self, value: &u16) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_u32(&mut self, value: &u32) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_u64(&mut self, value: &u64) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_u128(&mut self, value: &u128) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_string(&mut self, value: &String) {
        self.bytes.push(value.len() as u8);
        self.bytes.extend(value.as_bytes());
    }

    pub fn write_biguint(&mut self, value: &BigUint) {
        let bytes = value.to_bytes_be();
        self.bytes.push(bytes.len() as u8);
        self.bytes.extend(bytes);
    }

    pub fn write_optional_string(&mut self, opt: &Option<String>) {
        match opt {
            Some(v) => {
                self.write_string(v);
            },
            None => {
                self.bytes.push(0);
            }
        };
    }

    pub fn total_write(&self) -> usize {
        self.bytes.len()
    }

    pub fn bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Error, Debug)]
pub enum ReaderError {
    InvalidSize,
    InvalidValue,
    InvalidHex,
    ErrorTryInto
}

// Reader help us to read safely from bytes
// Mostly used when de-serializing an object from Serializer trait 
pub struct Reader<'a> {
    bytes: &'a[u8], // bytes to read
    total: usize // total read bytes
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader {
            bytes,
            total: 0
        }
    }

    pub fn read_bool(&mut self) -> Result<bool, ReaderError> {
        Ok(self.read_u8()? == 1)
    }

    pub fn read_bytes<T>(&mut self, n: usize) -> Result<T, ReaderError>
    where T: for<'b> std::convert::TryFrom<&'b[u8]> {
        if n > self.size() {
            return Err(ReaderError::InvalidSize)
        }

        let result = match self.bytes[self.total..self.total+n].try_into() {
            Ok(v) => {
                Ok(v)
            },
            Err(_) => Err(ReaderError::ErrorTryInto)
        };

        self.total += n;
        result
    }

    pub fn read_bytes_ref(&mut self, n: usize) -> Result<&[u8], ReaderError> {
        if n > self.size() {
            return Err(ReaderError::InvalidSize)
        }

        let bytes = &self.bytes[self.total..self.total+n];
        self.total += n;
        Ok(bytes)
    }

    pub fn read_bytes_32(&mut self) -> Result<[u8; 32], ReaderError> {
        self.read_bytes(32)
    }

    pub fn read_bytes_64(&mut self) -> Result<[u8; 64], ReaderError> {
        self.read_bytes(64)
    }

    pub fn read_hash(&mut self) -> Result<Hash, ReaderError> {
        Ok(Hash::new(self.read_bytes_32()?))
    }

    pub fn read_u8(&mut self) -> Result<u8, ReaderError> {
        if self.size() == 0 {
            return Err(ReaderError::InvalidSize)
        }
        let byte: u8 = self.bytes[self.total];
        self.total += 1;
        Ok(byte)
    }

    pub fn read_u16(&mut self) -> Result<u16, ReaderError> {
        Ok(u16::from_be_bytes(self.read_bytes(2)?))
    }

    pub fn read_u32(&mut self) -> Result<u32, ReaderError> {
        Ok(u32::from_be_bytes(self.read_bytes(4)?))
    }

    pub fn read_u64(&mut self) -> Result<u64, ReaderError> {
        Ok(u64::from_be_bytes(self.read_bytes(8)?))
    }

    pub fn read_u128(&mut self) -> Result<u128, ReaderError> {
        Ok(u128::from_be_bytes(self.read_bytes(16)?))
    }

    pub fn read_string_with_size(&mut self, size: usize) -> Result<String, ReaderError> {
        let bytes: Vec<u8> = self.read_bytes(size)?;
        match String::from_utf8(bytes) {
            Ok(v) => Ok(v),
            Err(_) => Err(ReaderError::InvalidValue)
        }
    }

    pub fn read_string(&mut self) -> Result<String, ReaderError> {
        let size = self.read_u8()?;
        self.read_string_with_size(size as usize)
    }

    pub fn read_optional_string(&mut self) -> Result<Option<String>, ReaderError> {
        match self.read_u8()? {
            0 => Ok(None),
            n => Ok(Some(self.read_string_with_size(n as usize)?)),
        }
    }

    pub fn read_big_uint(&mut self) -> Result<BigUint, ReaderError> {
        let size = self.read_u8()?;
        let bytes = self.read_bytes_ref(size as usize)?;
        Ok(BigUint::from_bytes_be(bytes))
    }

    pub fn total_size(&self) -> usize {
        self.bytes.len()
    }

    pub fn size(&self) -> usize {
        self.bytes.len() - self.total
    }

    pub fn total_read(&self) -> usize {
        self.total
    }
}

impl Display for ReaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        match self {
            ReaderError::ErrorTryInto => write!(f, "Error on try into"),
            ReaderError::InvalidSize => write!(f, "Invalid size"),
            ReaderError::InvalidValue => write!(f, "Invalid value"),
            ReaderError::InvalidHex => write!(f, "Invalid hex"),
        }
    }
}

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
                Serializer::read(&mut reader)
            },
            Err(_) => Err(ReaderError::InvalidHex)
        }
    }
}