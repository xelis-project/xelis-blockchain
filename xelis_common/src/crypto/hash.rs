use crate::serializer::{Writer, Serializer, ReaderError, Reader};
use std::{
    fmt::{Display, Error, Formatter},
    convert::TryInto,
    hash::Hasher,
    borrow::Cow,
};
use serde::de::Error as SerdeError;
use serde::{Deserialize, Serialize};
use blake3::hash as blake3_hash;

pub use xelis_hash::{
    Error as XelisHashError,
    xelis_hash,
    xelis_hash_no_scratch_pad,
    BYTES_ARRAY_INPUT,
    MEMORY_SIZE as POW_MEMORY_SIZE,
};

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

pub fn pow_hash(input: &[u8]) -> Result<Hash, XelisHashError> {
    if input.len() > BYTES_ARRAY_INPUT {
        return Err(XelisHashError);
    }

    let mut buffer = [0u8; BYTES_ARRAY_INPUT];
    buffer[..input.len()].copy_from_slice(input);
    xelis_hash_no_scratch_pad(buffer.as_mut_slice()).map(|bytes| Hash::new(bytes))
}

pub fn pow_hash_with_scratch_pad(input: &[u8], scratch_pad: &mut [u64; POW_MEMORY_SIZE]) -> Result<Hash, XelisHashError> {
    if input.len() > BYTES_ARRAY_INPUT {
        return Err(XelisHashError);
    }

    let mut buffer = [0u8; BYTES_ARRAY_INPUT];
    buffer[..input.len()].copy_from_slice(input);
    xelis_hash(buffer.as_mut_slice(), scratch_pad).map(|bytes| Hash::new(bytes))
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
        if hex.len() != 64 {
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

#[inline(always)]
pub fn hash(value: &[u8]) -> Hash {
    let result: [u8; HASH_SIZE] = blake3_hash(value).into();
    Hash(result)
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