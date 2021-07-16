use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::{PREFIX_ADDRESS, COIN_VALUE};
use ed25519_dalek::PublicKey;
use crate::bech32::*;

#[derive(Eq, Clone, Copy)]
pub struct Hash([u8; 32]);

impl Hash {

    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    pub fn zero() -> Self {
        Hash::new([0; 32])
    }

    pub fn as_bytes(&self) -> &[u8] {
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
    let result: [u8; 32] = crypto_hash::digest(crypto_hash::Algorithm::SHA256, value).try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Hash of length 32 but it was {}", v.len()));
    Hash(result)
}

pub fn get_current_time() -> u64 {
    let start = SystemTime::now();
    let time = start.duration_since(UNIX_EPOCH).expect("Incorrect time returned from get_current_time");
    time.as_secs()
}

pub fn format_coin(value: u64) -> String {
    format!("{}", value as f64 / COIN_VALUE as f64)
}

pub fn to_address(pub_key: &PublicKey) -> Result<String, Bech32Error> {
    let bits = convert_bits(pub_key.as_bytes(), 8, 5, true)?;
    let result = encode(PREFIX_ADDRESS.to_owned(), &bits)?;
    Ok(result)
}

pub fn as_address(pub_key: &PublicKey) -> String {
    match to_address(pub_key) {
        Ok(address) => address,
        Err(e) => panic!("{}", e)
    }
}