use std::array::TryFromSliceError;
use thiserror::Error;

use crate::crypto::Hash;

use super::Serializer;

#[derive(Error, Debug)]
pub enum ReaderError {
    #[error("Invalid size")]
    InvalidSize,
    #[error("Invalid value")]
    InvalidValue,
    #[error("Invalid hex")]
    InvalidHex,
    #[error("Error on try into")]
    ErrorTryInto,
    #[error(transparent)]
    TryFromSliceError(#[from] TryFromSliceError),
    #[error(transparent)]
    Any(anyhow::Error)
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

    pub fn read<T: Serializer>(&mut self) -> Result<T, ReaderError> {
        T::read(self)
    }

    pub fn read_bool(&mut self) -> Result<bool, ReaderError> {
        let byte = self.read_u8()?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ReaderError::InvalidValue)
        }
    }

    pub fn read_bytes<T>(&mut self, n: usize) -> Result<T, ReaderError>
    where T: for<'b> TryFrom<&'b [u8]> {
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

    pub fn read_optional_non_zero_u8(&mut self) -> Result<Option<u8>, ReaderError> {
        let byte = self.read_u8()?;
        if byte == 0 {
            return Ok(None)
        }

        Ok(Some(byte))
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
