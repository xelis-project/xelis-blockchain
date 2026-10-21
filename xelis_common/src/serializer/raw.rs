use crate::serializer::{
    Error as SerializationError,
    Readable,
    Reader,
    ReaderError,
    Serializer,
    Writable,
    Writer,
};
use std::ops::{Deref, DerefMut};


pub struct RawBytes(Vec<u8>);

impl RawBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serializer for RawBytes {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| writer.extend_bytes(&self.0))
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| reader.read_remaining_bytes().map(Self))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        Ok(self.0.clone())
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl Deref for RawBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for RawBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for RawBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<u8>> for RawBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<RawBytes> for Vec<u8> {
    fn from(raw: RawBytes) -> Self {
        raw.0
    }
}