mod hash;
mod address;
mod transcript;
mod human_readable_proof;

pub mod elgamal;
pub mod proofs;
pub mod bech32;

pub use hash::*;
pub use address::*;
pub use transcript::*;
pub use human_readable_proof::*;

pub use elgamal::{PrivateKey, KeyPair, Signature, SIGNATURE_SIZE};

/// Re-export the curve25519-dalek ecdlp module
pub use curve25519_dalek::ecdlp;

/// Public Key type used in the system
pub type PublicKey = elgamal::CompressedPublicKey;

use pooled_arc::impl_internable;

impl_internable!(Hash);
impl_internable!(PublicKey);
