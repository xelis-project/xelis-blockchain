mod defaults;
mod primitives;
mod reader;
mod hexable;
mod raw;
mod count;
mod dynamic_len;

use std::{any::type_name, marker::Sized};
use matriochka::ResultExt;
use octet::DecodeError as OctetDecodeError;

pub use reader::*;
pub use octet::{Readable, Reader, SliceSource, Writable, Writer};
pub use matriochka::{Error, Error as ReaderError};
pub use defaults::DEFAULT_MAX_ITEMS;
pub use hexable::*;
pub use raw::*;
pub use count::*;
pub use dynamic_len::*;

/// XELIS binary encoding over octet sources and sinks.
///
/// Reads and writes preserve their original error causes through Matriochka.
/// A failed write can leave a serialized prefix in the destination.
pub trait Serializer {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), Error>;

    /// Serialize to a buffer, preserving source errors and encoding context.
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::new();
        let mut writer = Writer::new(&mut buffer);
        ResultExt::with_context(
            self.write(&mut writer),
            || format!("serializing {}", type_name::<Self>()),
        )?;
        Ok(buffer)
    }

    fn to_hex(&self) -> Result<String, Error> {
        self.to_bytes().map(hex::encode)
    }

    fn size(&self) -> usize {
        self.to_bytes().expect("serialization for size calculation failed").len()
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError>
    where Self: Sized;

    fn from_hex(hex: &str) -> Result<Self, ReaderError>
    where Self: Sized {
        match hex::decode(hex) {
            Ok(bytes) => Self::from_bytes(&bytes),
            Err(error) => Err(Error::new(error))
        }
    }

    /// Deserialize a complete value from bytes.
    /// Returns an error if there are trailing bytes after the value.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ReaderError>
    where Self: Sized {
        let mut reader = Reader::new(bytes);
        let result = ResultExt::with_context(
            Self::read(&mut reader),
            || format!("deserializing {} at byte {}", type_name::<Self>(), reader.total_read()),
        )?;
        if reader.has_more() {
            return Err(Error::new(OctetDecodeError::TrailingBytes(reader.remaining()))
                .context(format!("decoding {} left unread bytes", type_name::<Self>())));
        }

        Ok(result)
    }

    /// Deserialize a value from the beginning of bytes and ignore trailing data.
    fn from_bytes_non_strict(bytes: &[u8]) -> Result<Self, ReaderError>
    where Self: Sized {
        let mut reader = Reader::new(bytes);
        ResultExt::with_context(
            Self::read(&mut reader),
            || format!("deserializing {} at byte {}", type_name::<Self>(), reader.total_read()),
        )
    }
}
