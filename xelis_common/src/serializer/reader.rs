use thiserror::Error;
use super::{Error as SerializationError, Readable, Reader, ReaderError, Serializer, Writer, Writable};

/// Protocol validation failures wrapped by Matriochka, alongside source errors.
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Invalid size")]
    InvalidSize,
    #[error("Invalid value")]
    InvalidValue,
}

// Skip N bytes before reading the next value.
pub struct Skip<const N: usize, T>(pub T);

impl<const N: usize, T: Serializer> Serializer for Skip<N, T> {
    fn write<'ty, 'r, W: Writable>(&self, _: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        Ok(())
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let mut remaining = N;
            let mut buffer = [0; 4096];
            while remaining > 0 {
                let count = remaining.min(buffer.len());
                reader.read_exact(&mut buffer[..count])?;
                remaining -= count;
            }
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
            if bool::read(reader)? {
                let mut remaining = N;
                let mut buffer = [0; 4096];
                while remaining > 0 {
                    let count = remaining.min(buffer.len());
                    reader.read_exact(&mut buffer[..count])?;
                    remaining -= count;
                }
            }
            T::read(reader).map(Self)
        })
    }
}
