pub const HASH_SIZE: usize = 32; //32 bytes / 256 bits

#[derive(Eq, Clone)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    pub fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Hash(bytes)
    }

    pub fn zero() -> Self {
        Hash::new([0; HASH_SIZE])
    }

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
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

use std::hash::Hasher;

impl std::hash::Hash for Hash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

use std::fmt::{Display, Error, Formatter};
impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", &self.to_hex())
    }
}

impl serde::Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

pub trait Hashable {
    fn to_bytes(&self) -> Vec<u8>;

    fn size(&self) -> usize {
        self.to_bytes().len()
    }

    fn hash(&self) -> Hash {
        let bytes = self.to_bytes();
        hash(&bytes)
    }
}

pub fn hash(value: &[u8]) -> Hash {
    use std::convert::TryInto;
    let result: [u8; HASH_SIZE] = crypto_hash::digest(crypto_hash::Algorithm::SHA256, value).try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Hash of length {} but it was {}", HASH_SIZE, v.len()));
    Hash(result)
}