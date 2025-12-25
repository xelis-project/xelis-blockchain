use std::ops::{Deref, DerefMut};

use super::{Reader, Serializer};

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
    fn write(&self, writer: &mut super::Writer) {
        writer.write_bytes(&self.0);
    }

    fn read(reader: &mut Reader) -> Result<Self, super::ReaderError> {
        let bytes = reader.read_bytes_left();
        Ok(Self(bytes.to_vec()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
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