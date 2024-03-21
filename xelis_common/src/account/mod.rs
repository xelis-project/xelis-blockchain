mod balance;
mod nonce;

use std::borrow::Cow;
use std::fmt::{self, Display, Formatter};

pub use balance::{VersionedBalance, BalanceType};
pub use nonce::VersionedNonce;
use serde::{Serialize, Deserialize};
use crate::crypto::elgamal::{Ciphertext, CompressedCiphertext, DecompressionError, RISTRETTO_COMPRESSED_SIZE};

use crate::serializer::{Reader, ReaderError, Serializer, Writer};

// Represents a Ciphertext that can be lazily decompressed and compressed
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CiphertextCache {
    Compressed(CompressedCiphertext),
    Decompressed(Ciphertext),
    Both(CompressedCiphertext, Ciphertext)
}

impl CiphertextCache {
    pub fn computable(&mut self) -> Result<&mut Ciphertext, DecompressionError> {
        Ok(match self {
            Self::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = Self::Decompressed(decompressed);
                match self {
                    Self::Decompressed(e) => e,
                    _ => unreachable!()
                }
            },
            Self::Decompressed(e) => e,
            Self::Both(_, e) => e
        })
    }

    pub fn compress<'a>(&'a self) -> Cow<'a, CompressedCiphertext> {
        match self {
            Self::Compressed(c) => Cow::Borrowed(c),
            Self::Decompressed(e) => Cow::Owned(e.compress()),
            Self::Both(c, _) => Cow::Borrowed(c)
        }
    }

    // Compress safely
    pub fn compressed<'a>(&'a mut self) -> &'a CompressedCiphertext {
        match self {
            Self::Compressed(c) => c,
            Self::Decompressed(e) => {
                *self = Self::Both(e.compress(), e.clone());
                match self {
                    Self::Both(c, _) => c,
                    _ => unreachable!()
                }
            },
            Self::Both(c, _) => c
        }
    }

    // Decompress without changing the current state
    pub fn decompressed<'a>(&'a mut self) -> Result<&'a Ciphertext, DecompressionError> {
        match self {
            Self::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = Self::Both(c.clone(), decompressed);
                match self {
                    Self::Both(_, e) => Ok(e),
                    _ => unreachable!()
                }
            },
            Self::Decompressed(e) => Ok(e),
            Self::Both(_, e) => Ok(e)
        }
    }

    pub fn both(&mut self) -> Result<(&CompressedCiphertext, &Ciphertext), DecompressionError> {
        match self {
            Self::Both(c, e) => Ok((c, e)),
            Self::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = Self::Both(c.clone(), decompressed);
                match self {
                    Self::Both(c, e) => Ok((c, e)),
                    _ => unreachable!()
                }
            },
            Self::Decompressed(e) => {
                let compressed = e.compress();
                *self = Self::Both(compressed, e.clone());
                match self {
                    Self::Both(c, e) => Ok((c, e)),
                    _ => unreachable!()
                }
            }
        }
    }

    pub fn take_ciphertext(self) -> Result<Ciphertext, DecompressionError> {
        Ok(match self {
            Self::Compressed(c) => c.decompress()?,
            Self::Decompressed(e) => e,
            Self::Both(_, e) => e
        })
    }
}

impl Serializer for CiphertextCache {
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

impl Serialize for CiphertextCache {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.compress().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CiphertextCache {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        CompressedCiphertext::deserialize(deserializer).map(Self::Compressed)
    }
}

impl Display for CiphertextCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "CiphertextCache[{}]", match self {
            Self::Compressed(c) => format!("Compressed({})", hex::encode(&c.to_bytes())),
            Self::Decompressed(e) => format!("Decompressed({})", hex::encode(&e.compress().to_bytes())),
            Self::Both(c, _) => format!("Both({})", hex::encode(&c.to_bytes()))
        })
    }
}