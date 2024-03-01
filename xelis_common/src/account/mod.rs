mod balance;
mod nonce;

use std::borrow::Cow;
pub use balance::VersionedBalance;
pub use nonce::VersionedNonce;
use serde::{Serialize, Deserialize};
use crate::crypto::elgamal::{Ciphertext, CompressedCiphertext, DecompressionError, RISTRETTO_COMPRESSED_SIZE};

use crate::serializer::{Reader, ReaderError, Serializer, Writer};

// Represents a Ciphertext
#[derive(Clone, Debug)]
pub enum CiphertextVariant {
    Compressed(CompressedCiphertext),
    Decompressed(Ciphertext)
}

impl CiphertextVariant {
    // Get a reference to the inner ElGamalCiphertext for operations
    pub fn get_mut<'a>(&'a mut self) -> Result<&'a mut Ciphertext, DecompressionError> {
        match self {
            Self::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = Self::Decompressed(decompressed);
                Ok(match self {
                    Self::Decompressed(e) => e,
                    _ => unreachable!()
                })
            },
            Self::Decompressed(c) => Ok(c)
        }
    }

    // Compress without changing the current state
    pub fn compress<'a>(&'a self) -> Cow<'a, CompressedCiphertext> {
        match self {
            Self::Compressed(c) => Cow::Borrowed(c),
            Self::Decompressed(e) => Cow::Owned(e.compress())
        }
    }

    // Decompress without changing the current state
    pub fn decompress<'a>(&'a self) -> Result<Cow<'a, Ciphertext>, DecompressionError> {
        match self {
            Self::Compressed(c) => Ok(Cow::Owned(c.decompress()?)),
            Self::Decompressed(e) => Ok(Cow::Borrowed(e))
        }
    }

    pub fn take(self) -> Result<Ciphertext, DecompressionError> {
        let ct = match self {
            Self::Compressed(c) => c.decompress()?,
            Self::Decompressed(e) => e
        };
        Ok(ct)
    }
}

impl Serializer for CiphertextVariant {
    fn write(&self, writer: &mut Writer) {
        self.compress().write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let compressed = CompressedCiphertext::read(reader)?;
        Ok(Self::Compressed(compressed))
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE + RISTRETTO_COMPRESSED_SIZE
    }
}

impl Serialize for CiphertextVariant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.compress().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CiphertextVariant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        CompressedCiphertext::deserialize(deserializer).map(Self::Compressed)
    }
}