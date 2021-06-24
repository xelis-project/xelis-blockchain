use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Hash = [u8; 32];

pub trait Hashable {
    fn to_bytes(&self) -> Vec<u8>;

    fn size(&self) -> usize { //in byte
        self.to_bytes().len()
    }

    fn hash(&self) -> Hash {
        let bytes = self.to_bytes();
        hash(&bytes)
    }
}

pub fn hash(value: &[u8]) -> Hash {
    crypto_hash::digest(crypto_hash::Algorithm::SHA256, value).try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Hash of length 32 but it was {}", v.len()))
}

pub fn get_current_time() -> u64 {
    let start = SystemTime::now();
    let time = start.duration_since(UNIX_EPOCH).expect("Incorrect time returned from get_current_time");
    time.as_secs()
}