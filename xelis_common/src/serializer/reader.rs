use octet::DecodeError as OctetDecodeError;
use thiserror::Error;
use crate::crypto::Hash;
use super::{Error as SerializationError, Readable, Reader, ReaderError, Serializer, Writer, Writable};

/// Protocol validation failures wrapped by Matriochka, alongside source errors.
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Invalid size")]
    InvalidSize,
    #[error("Invalid value")]
    InvalidValue,
}

/// XELIS decoding helpers for any octet byte source.
pub trait ReaderExt {
    fn read<T: Serializer>(&mut self) -> Result<T, ReaderError>;
    fn read_exact_bytes(&mut self, bytes: &mut [u8]) -> Result<(), ReaderError>;
    fn read_vec_bytes(&mut self, size: usize) -> Result<Vec<u8>, ReaderError>;
    /// Read an unframed value through EOF. Embedded values need a bounded source.
    fn read_all_bytes(&mut self) -> Result<Vec<u8>, ReaderError>;

    fn skip(&mut self, mut n: usize) -> Result<(), ReaderError> {
        let mut buffer = [0; 4096];
        while n > 0 {
            let count = n.min(buffer.len());
            self.read_exact_bytes(&mut buffer[..count])?;
            n -= count;
        }
        Ok(())
    }

    fn read_bool(&mut self) -> Result<bool, ReaderError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(SerializationError::new(DecodeError::InvalidValue).context(format!("invalid boolean byte {tag}; expected 0 or 1"))),
        }
    }

    fn read_bytes_32(&mut self) -> Result<[u8; 32], ReaderError> {
        let mut bytes = [0; 32];
        self.read_exact_bytes(&mut bytes)?;
        Ok(bytes)
    }

    fn read_bytes_64(&mut self) -> Result<[u8; 64], ReaderError> {
        let mut bytes = [0; 64];
        self.read_exact_bytes(&mut bytes)?;
        Ok(bytes)
    }

    fn read_hash(&mut self) -> Result<Hash, ReaderError> {
        self.read_bytes_32().map(Hash::new)
    }

    fn read_u8(&mut self) -> Result<u8, ReaderError> {
        let mut bytes = [0];
        self.read_exact_bytes(&mut bytes)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, ReaderError> {
        let mut bytes = [0; 2];
        self.read_exact_bytes(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, ReaderError> {
        let mut bytes = [0; 4];
        self.read_exact_bytes(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, ReaderError> {
        let mut bytes = [0; 8];
        self.read_exact_bytes(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_u128(&mut self) -> Result<u128, ReaderError> {
        let mut bytes = [0; 16];
        self.read_exact_bytes(&mut bytes)?;
        Ok(u128::from_be_bytes(bytes))
    }

    fn read_string_with_size(&mut self, size: usize) -> Result<String, ReaderError> {
        let bytes = self.read_vec_bytes(size)?;
        String::from_utf8(bytes).map_err(|error| SerializationError::new(error)
            .context(format!("decoding a UTF-8 string of {size} bytes")))
    }

    fn read_string(&mut self) -> Result<String, ReaderError> {
        let size = self.read_u8()? as usize;
        self.read_string_with_size(size)
    }

    fn read_optional_string(&mut self) -> Result<Option<String>, ReaderError> {
        match self.read_u8()? {
            0 => Ok(None),
            n => self.read_string_with_size(n as usize).map(Some),
        }
    }

    fn read_optional_non_zero_u8(&mut self) -> Result<Option<u8>, ReaderError> {
        let value = self.read_u8()?;
        Ok((value != 0).then_some(value))
    }

    fn read_optional_non_zero_u16(&mut self) -> Result<Option<u16>, ReaderError> {
        let value = self.read_u16()?;
        Ok((value != 0).then_some(value))
    }

    fn read_optional_non_zero_u64(&mut self) -> Result<Option<u64>, ReaderError> {
        let value = self.read_u64()?;
        Ok((value != 0).then_some(value))
    }
}

impl<'ty, 'r, R: Readable> ReaderExt for Reader<'ty, 'r, R> {
    fn read<T: Serializer>(&mut self) -> Result<T, ReaderError> {
        T::read(self)
    }

    fn read_exact_bytes(&mut self, bytes: &mut [u8]) -> Result<(), ReaderError> {
        self.read_exact(bytes)
    }

    fn read_vec_bytes(&mut self, size: usize) -> Result<Vec<u8>, ReaderError> {
        self.read_vec(size)
    }

    fn read_all_bytes(&mut self) -> Result<Vec<u8>, ReaderError> {
        // octet treats an empty unframed value as an error; XELIS permits it.
        match self.read_remaining_bytes() {
            Err(error) if error.chain().count() == 1 && matches!(error.downcast_ref::<OctetDecodeError>(),
                Some(OctetDecodeError::OutOfBounds { requested: 1, available: 0 })) => Ok(Vec::new()),
            result => result,
        }
    }
}

// Skip N bytes before reading the next value.
pub struct Skip<const N: usize, T>(pub T);

impl<const N: usize, T: Serializer> Serializer for Skip<N, T> {
    fn write<'ty, 'r, W: Writable>(&self, _: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        Ok(())
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            reader.skip(N)?;
            T::read(reader).map(Self)
        })
    }
}

pub struct SkipIf<const N: usize, T>(pub T);

impl<const N: usize, T: Serializer> Serializer for SkipIf<N, T> {
    fn write<'ty, 'r, W: Writable>(&self, _: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        Ok(())
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            if reader.read_bool()? {
                reader.skip(N)?;
            }
            T::read(reader).map(Self)
        })
    }
}
