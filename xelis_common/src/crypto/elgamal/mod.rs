use lazy_static::lazy_static;
use sha3::Digest;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_COMPRESSED,
    ristretto::RistrettoPoint
};

mod compressed;
mod ciphertext;
mod key;
mod signature;
mod pedersen;

pub use compressed::{CompressedCiphertext, CompressedCommitment, CompressedHandle, CompressedPublicKey, DecompressionError, RISTRETTO_COMPRESSED_SIZE};
pub use ciphertext::Ciphertext;
pub use key::{KeyPair, PrivateKey, PublicKey};
pub use pedersen::{DecryptHandle, PedersenCommitment, PedersenOpening};

pub use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

lazy_static! {
    // base point for encoding the commitments opening
    pub static ref H: RistrettoPoint = {
        let mut hasher = sha3::Sha3_512::default();
        hasher.update(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
        let hash = hasher.finalize();
        RistrettoPoint::from_uniform_bytes(hash.as_ref())
    };
}
