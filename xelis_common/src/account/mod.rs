mod balance;
mod nonce;

use std::borrow::Cow;
pub use balance::VersionedBalance;
pub use nonce::VersionedNonce;
use serde::{Serialize, Deserialize};
use xelis_he::{CompressedCiphertext, DecompressionError, ElGamalCiphertext};

use crate::serializer::{Reader, ReaderError, Serializer, Writer};

// Represents a Ciphertext
#[derive(Clone, Debug)]
pub enum Ciphertext {
    Compressed(CompressedCiphertext),
    Decompressed(ElGamalCiphertext)
}

impl Ciphertext {
    // Get a reference to the inner ElGamalCiphertext for operations
    pub fn get_mut<'a>(&'a mut self) -> Result<&'a mut ElGamalCiphertext, DecompressionError> {
        match self {
            Ciphertext::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = Ciphertext::Decompressed(decompressed);
                Ok(match self {
                    Ciphertext::Decompressed(e) => e,
                    _ => unreachable!()
                })
            },
            Ciphertext::Decompressed(c) => Ok(c)
        }
    }

    // Compress without changing the current state
    pub fn compress<'a>(&'a self) -> Cow<'a, CompressedCiphertext> {
        match self {
            Ciphertext::Compressed(c) => Cow::Borrowed(c),
            Ciphertext::Decompressed(e) => Cow::Owned(e.compress())
        }
    }

    // Decompress without changing the current state
    pub fn decompress<'a>(&'a self) -> Result<Cow<'a, ElGamalCiphertext>, DecompressionError> {
        match self {
            Ciphertext::Compressed(c) => Ok(Cow::Owned(c.decompress()?)),
            Ciphertext::Decompressed(e) => Ok(Cow::Borrowed(e))
        }
    }

    pub fn take(self) -> Result<ElGamalCiphertext, DecompressionError> {
        let ct = match self {
            Ciphertext::Compressed(c) => c.decompress()?,
            Ciphertext::Decompressed(e) => e
        };
        Ok(ct)
    }
}

impl Serializer for Ciphertext {
    fn write(&self, writer: &mut Writer) {
        self.compress().write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let compressed = CompressedCiphertext::read(reader)?;
        Ok(Self::Compressed(compressed))
    }

    fn size(&self) -> usize {
        32 + 32
    }
}

impl Serializer for CompressedCiphertext {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(&self.0[0]);
        writer.write_bytes(&self.0[1]);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let left = reader.read_bytes(32)?;
        let right = reader.read_bytes(32)?;
        let compress = CompressedCiphertext([left, right]);
        Ok(compress)
    }

    fn size(&self) -> usize {
        32 + 32
    }
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.compress().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        CompressedCiphertext::deserialize(deserializer).map(Ciphertext::Compressed)
    }
}