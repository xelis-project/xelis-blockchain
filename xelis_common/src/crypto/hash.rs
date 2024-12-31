use crate::{block::Algorithm, serializer::{Reader, ReaderError, Serializer, Writer}};
use std::{
    borrow::Cow,
    convert::TryInto,
    fmt::{Display, Error, Formatter},
    hash::Hasher,
    str::FromStr
};
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use blake3::hash as blake3_hash;

pub use xelis_hash::Error as XelisHashError;
use xelis_hash::{v1, v2};

pub const HASH_SIZE: usize = 32; // 32 bytes / 256 bits

#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Debug)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    pub const fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Hash(bytes)
    }

    pub const fn zero() -> Self {
        Hash::new([0; HASH_SIZE])
    }

    pub const fn max() -> Self {
        Hash::new([u8::MAX; HASH_SIZE])
    }

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl FromStr for Hash {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| "Invalid hex string")?;
        let bytes: [u8; HASH_SIZE] = bytes.try_into().map_err(|_| "Invalid hash")?;
        Ok(Hash::new(bytes))
    }
}

// Hash a byte array using the blake3 algorithm
#[inline(always)]
pub fn hash(value: &[u8]) -> Hash {
    let result: [u8; HASH_SIZE] = blake3_hash(value).into();
    Hash(result)
}

// Perform a PoW hash using the given algorithm
pub fn pow_hash(work: &[u8], algorithm: Algorithm) -> Result<Hash, XelisHashError> {
    match algorithm {
        Algorithm::V1 => {
            let mut scratchpad = v1::ScratchPad::default();

            // Make sure the input has good alignment
            let mut input = v1::AlignedInput::default();
            let slice = input.as_mut_slice()?;
            slice[..work.len()].copy_from_slice(work);
        
            v1::xelis_hash(slice, &mut scratchpad).map(|bytes| Hash::new(bytes))
        },
        Algorithm::V2 => {
            let mut scratchpad = v2::ScratchPad::default();
            v2::xelis_hash(work, &mut scratchpad).map(|bytes| Hash::new(bytes))
        },
    }
}

impl Serializer for Hash {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let hash = reader.read_hash()?;
        Ok(hash)
    }

    fn write(&self, writer: &mut Writer) {
        writer.write_hash(self);
    }

    fn size(&self) -> usize {
        HASH_SIZE
    }
}

impl std::hash::Hash for Hash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl AsRef<Hash> for Hash {
    fn as_ref(&self) -> &Hash {
        self
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", &self.to_hex())
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'a> Deserialize<'a> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'a> {
        let hex = String::deserialize(deserializer)?;
        if hex.len() != HASH_SIZE * 2 {
            return Err(SerdeError::custom("Invalid hex length"))
        }

        let decoded_hex = hex::decode(hex).map_err(SerdeError::custom)?;
        let bytes: [u8; 32] = decoded_hex.try_into().map_err(|_| SerdeError::custom("Could not transform hex to bytes array for Hash"))?;
        Ok(Hash::new(bytes))
    }
}

pub trait Hashable: Serializer {
    #[inline(always)]
    fn hash(&self) -> Hash {
        let bytes = self.to_bytes();
        hash(&bytes)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> Into<Cow<'a, Hash>> for Hash {
    fn into(self) -> Cow<'a, Hash> {
        Cow::Owned(self)
    }
}

impl<'a> Into<Cow<'a, Hash>> for &'a Hash {
    fn into(self) -> Cow<'a, Hash> {
        Cow::Borrowed(self)
    }
}