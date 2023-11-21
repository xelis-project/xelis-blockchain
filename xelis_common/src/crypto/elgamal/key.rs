use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, constants::RISTRETTO_BASEPOINT_TABLE};
use rand::rngs::OsRng;

use crate::crypto::hash::Hash;

use super::{Ciphertext, signature::{hash_and_point_to_scalar, Signature}};

pub struct PrivateKey {
    secret: Scalar
}

impl PrivateKey {
    pub fn new(secret: Scalar) -> Self {
        Self {
            secret
        }
    }

    // Sign a hash
    pub fn sign(&self, hash: &Hash) -> Signature {
        let k = Scalar::random(&mut OsRng);
        let r = &RISTRETTO_BASEPOINT_TABLE * &k;
        let e = hash_and_point_to_scalar(&self.to_public_key(), hash, &r);
        let s = self.secret * e + k;
        Signature::new(s, e)
    }

    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::new(&self.secret * &RISTRETTO_BASEPOINT_TABLE)
    }

    pub fn decrypt_to_point(&self, ciphertext: &Ciphertext) -> RistrettoPoint {
        let (left, right) = ciphertext.points();
        right - left * &self.secret
    }
}

pub struct PublicKey {
    point: RistrettoPoint
}

impl PublicKey {
    pub fn new(point: RistrettoPoint) -> Self {
        Self {
            point
        }
    }

    pub fn point(&self) -> &RistrettoPoint {
        &self.point
    }

    // Generate a random Scalar to be used as blinding factor for encryption
    pub fn generate_random_r(&self) -> Scalar {
        // Create a random number generator
        let r = Scalar::random(&mut OsRng);
        r
    }

    pub fn encrypt(&self, value: u64) -> Ciphertext {
        let m = &Scalar::from(value) * &RISTRETTO_BASEPOINT_TABLE;
        self.encrypt_point(m)
    }
    
    pub fn encrypt_point(&self, m: RistrettoPoint) -> Ciphertext {
        let r = self.generate_random_r();
        self.encrypt_with(m, r)
    }

    pub fn encrypt_with(&self, m: RistrettoPoint, r: Scalar) -> Ciphertext {
        let c1 = &r * &RISTRETTO_BASEPOINT_TABLE;
        let c2 = m + r * &self.point;
        Ciphertext::new(c1, c2)
    }
}