use curve25519_dalek::{scalar::Scalar, constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint};
use ed25519_dalek::Sha512;

use crate::crypto::hash::Hash;

use super::PublicKey;

// This file implements a Schnorr Signature
// It use SHA-512 to provide a 64-bytes (512 bits) hash
pub struct Signature {
    s: Scalar,
    e: Scalar
}

impl Signature {
    pub fn new(s: Scalar, e: Scalar) -> Self {
        Self {
            s,
            e
        }
    }

    // Verify the signature using the Public Key and the hash of the message
    pub fn verify(&self, hash: &Hash, key: &PublicKey) -> bool {
        let r = &RISTRETTO_BASEPOINT_TABLE * &self.s + key.point() * -self.e;
        let calculated = hash_and_point_to_scalar(&key, hash, &r);
        self.e == calculated
    }
}

// Create a Scalar from Public Key, Hash of the message, and selected point
pub fn hash_and_point_to_scalar(key: &PublicKey, message_hash: &Hash, point: &RistrettoPoint) -> Scalar {
    let mut data = [0u8; 96];
    data[0..32].copy_from_slice(key.point().compress().as_bytes());
    data[32..64].copy_from_slice(message_hash.as_bytes());
    data[64..96].copy_from_slice(point.compress().as_bytes());
    Scalar::hash_from_bytes::<Sha512>(&data)
}

mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    use crate::crypto::{elgamal::{PrivateKey, PublicKey}, hash::{hash, Hash}};

    fn _generate_key_pair() -> (PrivateKey, PublicKey) {
        let private_key = PrivateKey::new(Scalar::random(&mut OsRng));
        let public_key = private_key.to_public_key();
        (private_key, public_key)
    }

    fn _create_message_hash(message: &[u8]) -> Hash {
        hash(message)
    }

    // Generate a signature for a message and verify it
    #[test]
    fn test_signature() {
        let (private_key, public_key) = _generate_key_pair();
        let message_hash = _create_message_hash(b"Hello World!");
        let signature = private_key.sign(&message_hash);

        assert!(signature.verify(&message_hash, &public_key), "Signature verification failed");
    }

    // Generate a signature for a message and verify that it is incorrect
    #[test]
    fn test_signature_invalid() {
        let (private_key, _) = _generate_key_pair();
        let message_hash = _create_message_hash(b"Hello World!");
        let signature = private_key.sign(&message_hash);

        // Verify the signature with the wrong key
        let (_, public_key) = _generate_key_pair();
        assert!(!signature.verify(&message_hash, &public_key), "Signature should fail");
    }
}