mod hash;
mod address;
mod transcript;
mod human_readable_proof;

pub mod elgamal;
pub mod proofs;
pub mod bech32;

use rand::{CryptoRng, TryCryptoRng};
use curve25519_dalek::Scalar;

pub use hash::*;
pub use address::*;
pub use transcript::*;
pub use human_readable_proof::*;

pub use elgamal::{PrivateKey, KeyPair, Signature, SIGNATURE_SIZE};

/// Re-export the curve25519-dalek ecdlp module
pub use curve25519_dalek::ecdlp;


/// Generate a non-zero random scalar
pub fn non_zero_random_scalar<R: CryptoRng + ?Sized>(rng: &mut R) -> Scalar {
    loop {
        let scalar = Scalar::random(rng);

        if scalar != Scalar::ZERO {
            return scalar
        }
    }
}

/// Random generator that implements CryptoRng
#[inline(always)]
pub fn rng() -> impl CryptoRng + TryCryptoRng {
    rand::rng()
}

/// Public Key type used in the system
pub type PublicKey = elgamal::CompressedPublicKey;

use pooled_arc::impl_internable;

impl_internable!(Hash);
impl_internable!(PublicKey);
