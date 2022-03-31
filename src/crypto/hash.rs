use crate::core::serializer::Serializer;
use std::fmt::{Display, Error, Formatter};
use sha2::{Sha256, Digest};
use std::convert::TryInto;
use std::hash::Hasher;

pub const HASH_SIZE: usize = 32; // 32 bytes / 256 bits

#[derive(Eq, Clone, Debug)]
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

impl PartialEq for Hash {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl std::hash::Hash for Hash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", &self.to_hex())
    }
}

impl serde::Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

pub trait Hashable: Serializer {
    fn hash(&self) -> Hash {
        let bytes = self.to_bytes();
        hash(&bytes)
    }
}

pub fn hash(value: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value);
    let result: [u8; HASH_SIZE] = hasher.finalize()[..].try_into().unwrap();
    Hash(result)
}