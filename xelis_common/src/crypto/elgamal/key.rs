use curve25519_dalek::{ristretto::RistrettoPoint, Scalar};
use rand::rngs::OsRng;
use super::{ciphertext::Ciphertext, pedersen::{DecryptHandle, PedersenCommitment, PedersenOpening}, H};

pub struct PublicKey(RistrettoPoint);

pub struct PrivateKey(Scalar);

pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl PublicKey {
    pub fn from_point(p: RistrettoPoint) -> Self {
        Self(p)
    }

    pub fn new(secret: &PrivateKey) -> Self {
        let s = &secret.0;
        assert!(s != &Scalar::ZERO);

        Self(s.invert() * *H)
    }

    pub fn encrypt<T: Into<Scalar>>(&self, amount: T) -> Ciphertext {
        let (commitment, opening) = PedersenCommitment::new(amount);
        let handle = self.decrypt_handle(&opening);

        Ciphertext::new(commitment, handle)
    }

    pub fn encrypt_with_opening<T: Into<Scalar>>(
        &self,
        amount: T,
        opening: &PedersenOpening,
    ) -> Ciphertext {
        let commitment = PedersenCommitment::new_with_opening(amount, opening);
        let handle = self.decrypt_handle(opening);

        Ciphertext::new(commitment, handle)
    }

    pub fn decrypt_handle(&self, opening: &PedersenOpening) -> DecryptHandle {
        DecryptHandle::new(&self, opening)
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }
}

impl PrivateKey {
    // Create a new private key from a scalar
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self(scalar)
    }

    // Returns the private key as a scalar
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    pub fn decrypt_to_point(&self, ciphertext: &Ciphertext) -> RistrettoPoint {
        let commitment = ciphertext.commitment().as_point();
        let handle = ciphertext.handle().as_point();

        commitment - &(self.0 * handle)
    }
}

impl KeyPair {
    // Generate a random new KeyPair
    pub fn new() -> Self {
        let scalar = Scalar::random(&mut OsRng);
        let private_key = PrivateKey::from_scalar(scalar);

        Self::from_private_key(private_key)
    }

    // Generate a key pair from a private key
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let public_key = PublicKey::new(&private_key);
        Self {
            public_key,
            private_key,
        }
    }

    // Create a new key pair from a public and private key
    pub fn from_keys(public_key: PublicKey, private_key: PrivateKey) -> Self {
        KeyPair {
            public_key,
            private_key,
        }
    }

    // Get the public key of the KeyPair
    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    // Get the private key of the KeyPair
    pub fn get_private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::traits::Identity;

    use super::*;
    use super::super::G;

    #[test]
    fn test_encrypt_decrypt() {
        let keypair = KeyPair::new();
        let public_key = keypair.get_public_key();
        let private_key = keypair.get_private_key();

        let amount = Scalar::from(10u64);
        let ciphertext = public_key.encrypt(amount);

        let decrypted = private_key.decrypt_to_point(&ciphertext);
        assert_eq!(decrypted, amount * &G);
    }

    #[test]
    fn test_identity() {
        let keypair = KeyPair::new();
        let public_key = keypair.get_public_key();
        let private_key = keypair.get_private_key();

        let amount = Scalar::from(0u64);
        let ciphertext = public_key.encrypt(amount);
        let decrypted = private_key.decrypt_to_point(&ciphertext);
        assert_eq!(decrypted, RistrettoPoint::identity());
    }

    #[test]
    fn test_universal_identity() {
        let keypair = KeyPair::new();
        let private_key = keypair.get_private_key();

        let ciphertext = Ciphertext::zero();
        let decrypted = private_key.decrypt_to_point(&ciphertext);
        assert_eq!(decrypted, RistrettoPoint::identity());
    }

    #[test]
    fn test_homomorphic_add() {
        let keypair = KeyPair::new();
        let public_key = keypair.get_public_key();
        let private_key = keypair.get_private_key();

        let amount1 = Scalar::from(10u64);
        let amount2 = Scalar::from(20u64);
        let c1 = public_key.encrypt(amount1);
        let c2 = public_key.encrypt(amount2);

        let sum = c1 + c2;
        let decrypted = private_key.decrypt_to_point(&sum);
        assert_eq!(decrypted, (amount1 + amount2) * &G);
    }

    #[test]
    fn test_homomorphic_add_scalar() {
        let keypair = KeyPair::new();
        let public_key = keypair.get_public_key();
        let private_key = keypair.get_private_key();

        let amount1 = Scalar::from(10u64);
        let amount2 = Scalar::from(20u64);
        let c1 = public_key.encrypt(amount1);

        let sum = c1 + amount2;
        let decrypted = private_key.decrypt_to_point(&sum);
        assert_eq!(decrypted, (amount1 + amount2) * &G);
    }

    #[test]
    fn test_homomorphic_sub() {
        let keypair = KeyPair::new();
        let public_key = keypair.get_public_key();
        let private_key = keypair.get_private_key();

        let amount1 = Scalar::from(20u64);
        let amount2 = Scalar::from(10u64);
        let c1 = public_key.encrypt(amount1);
        let c2 = public_key.encrypt(amount2);

        let sub = c1 - c2;
        let decrypted = private_key.decrypt_to_point(&sub);
        assert_eq!(decrypted, (amount1 - amount2) * &G);
    }

    #[test]
    fn test_homomorphic_sub_scalar() {
        let keypair = KeyPair::new();
        let public_key = keypair.get_public_key();
        let private_key = keypair.get_private_key();

        let amount1 = Scalar::from(20u64);
        let amount2 = Scalar::from(10u64);
        let c1 = public_key.encrypt(amount1);

        let sub = c1 - amount2;
        let decrypted = private_key.decrypt_to_point(&sub);
        assert_eq!(decrypted, (amount1 - amount2) * &G);
    }
}