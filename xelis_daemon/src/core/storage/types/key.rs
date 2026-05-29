use std::ops::{Deref, DerefMut};

use xelis_common::{block::TopoHeight, serializer::*};

/// A versioned key is a key that is prefixed with a topoheight. It is used to store versioned data on disk.
pub struct VersionedKey(Key);

impl VersionedKey {
    #[inline(always)]
    pub fn new(topoheight: TopoHeight) -> Self {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&topoheight.to_be_bytes());
        Self(Key::from(buffer))
    }

    #[inline(always)]
    pub fn extend_with<T: AsRef<[u8]>>(&mut self, key: T) {
        self.0.extend_with(key);
    }
}

impl AsRef<[u8]> for VersionedKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for VersionedKey {
    type Target = Key;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for VersionedKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serializer for VersionedKey {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(_: &mut Reader) -> Result<Self, ReaderError> {
        Err(ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

pub struct Key(Vec<u8>);

impl Key {
    #[inline(always)]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    #[inline(always)]
    pub fn extend_with<T: AsRef<[u8]>>(&mut self, key: T) {
        self.0.extend_from_slice(key.as_ref());
    }
}

impl From<Vec<u8>> for Key {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Into<Vec<u8>> for Key {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl Serializer for Key {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(&self.0);
    }

    fn read(_: &mut Reader) -> Result<Self, ReaderError> {
        Err(ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}