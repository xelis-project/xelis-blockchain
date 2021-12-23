use std::convert::TryInto;

pub enum ReaderError {
    InvalidSize,
    InvalidValue,
    ErrorTryInto
}

pub struct Reader {
    bytes: Vec<u8>, // bytes to read
    total: usize // total read bytes
}

impl Reader {
    pub fn new(bytes: Vec<u8>) -> Self {
        Reader {
            bytes,
            total: 0
        }
    }

    pub fn try_into<T>(&mut self, n: usize) -> Result<T, ReaderError>
    where T: for<'a> std::convert::TryFrom<&'a[u8]> {
        if n > self.size() {
            return Err(ReaderError::InvalidSize)
        }

        let result = match self.bytes[0..n].try_into() {
            Ok(v) => {
                Ok(v)
            },
            Err(_) => Err(ReaderError::ErrorTryInto)
        };

        self.total += n;
        self.bytes.drain(..n); // is there a better way ?
        result
    }

    pub fn read_bytes_32(&mut self) -> Result<[u8; 32], ReaderError> {
        self.try_into(32)
    }

    pub fn read_bytes_64(&mut self) -> Result<[u8; 64], ReaderError> {
        self.try_into(64)
    }

    pub fn read_u8(&mut self) -> Result<u8, ReaderError> {
        if self.size() == 0 {
            return Err(ReaderError::InvalidSize)
        }
        self.total += 1;
        Ok(self.bytes.remove(0))
    }

    pub fn read_u16(&mut self) -> Result<u16, ReaderError> {
        Ok(u16::from_be_bytes(self.try_into(2)?))
    }

    pub fn read_u64(&mut self) -> Result<u64, ReaderError> {
        Ok(u64::from_be_bytes(self.try_into(8)?))
    }

    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    pub fn total_read(&self) -> usize {
        self.total
    }
}

use std::fmt::{Display, Error, Formatter};

impl Display for ReaderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        match self {
            ReaderError::ErrorTryInto => write!(f, "Error on try into"),
            ReaderError::InvalidSize => write!(f, "Invalid size"),
            ReaderError::InvalidValue => write!(f, "Invalid value"),
        }
    }
}