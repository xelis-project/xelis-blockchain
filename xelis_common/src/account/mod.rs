mod balance;
mod nonce;

use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter}
};
pub use balance::{VersionedBalance, BalanceType, AccountSummary, Balance};
pub use nonce::{VersionedNonce, Nonce};
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};
use crate::{
        crypto::elgamal::{
        Ciphertext,
        CompressedCiphertext,
        DecompressionError,
        RISTRETTO_COMPRESSED_SIZE
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};

// Represents a Ciphertext that can be lazily decompressed and compressed
#[derive(Clone, Debug, JsonSchema)]
pub enum CiphertextCache {
    Compressed(CompressedCiphertext),
    #[schemars(skip)]
    Decompressed(Option<CompressedCiphertext>, Ciphertext),
}

impl CiphertextCache {
    pub fn computable(&mut self) -> Result<&mut Ciphertext, DecompressionError> {
        Ok(match self {
            Self::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = Self::Decompressed(None, decompressed);
                match self {
                    Self::Decompressed(_, e) => e,
                    _ => unreachable!()
                }
            },
            Self::Decompressed(compressed, e) => {
                // Delete the compressed cache to prevent any issue
                *compressed = None;
                e
            },
        })
    }

    pub fn compress<'a>(&'a self) -> Cow<'a, CompressedCiphertext> {
        match self {
            Self::Compressed(c) => Cow::Borrowed(c),
            Self::Decompressed(e, d) => match e {
                Some(c) => Cow::Borrowed(c),
                None => Cow::Owned(d.compress())
            },
        }
    }

    // Compress safely
    pub fn compressed<'a>(&'a mut self) -> &'a CompressedCiphertext {
        match self {
            Self::Compressed(c) => c,
            Self::Decompressed(e, d) => match e {
                Some(c) => c,
                None => e.insert(d.compress())
            },
        }
    }

    // Decompress without changing the current state
    pub fn decompressed<'a>(&'a mut self) -> Result<&'a Ciphertext, DecompressionError> {
        match self {
            Self::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = Self::Decompressed(Some(c.clone()), decompressed);
                match self {
                    Self::Decompressed(_, e) => Ok(e),
                    _ => unreachable!()
                }
            },
            Self::Decompressed(_, e) => Ok(e),
        }
    }

    pub fn both(&mut self) -> Result<(&CompressedCiphertext, &Ciphertext), DecompressionError> {
        match self {
            Self::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = Self::Decompressed(Some(c.clone()), decompressed);
                match self {
                    Self::Decompressed(Some(c), e) => Ok((c, e)),
                    _ => unreachable!()
                }
            },
            Self::Decompressed(c, e) => {
                let compressed = match c {
                    Some(c) => c,
                    None => c.insert(e.compress()),
                };

                Ok((compressed, e))
            }
        }
    }

    pub fn take_ciphertext(self) -> Result<Ciphertext, DecompressionError> {
        Ok(match self {
            Self::Compressed(c) => c.decompress()?,
            Self::Decompressed(_, e) => e,
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
            Self::Decompressed(c, e) => format!("Decompressed({}, {})", c.as_ref().map(|v| hex::encode(&v.to_bytes())).unwrap_or_default(), hex::encode(&e.compress().to_bytes())),
        })
    }
}

impl PartialEq for CiphertextCache {
    fn eq(&self, other: &Self) -> bool {
        let a = self.compress();
        let b = other.compress();
        a == b
    }
}

impl Eq for CiphertextCache {}