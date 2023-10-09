mod ciphertext;
mod key;

pub use self::{
    ciphertext::Ciphertext,
    key::{PrivateKey, PublicKey},
};

mod tests {
    use curve25519_dalek::{scalar::Scalar, constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint};
    use rand::rngs::OsRng;
    use super::{PrivateKey, PublicKey};

    fn _generate_key_pair() -> (PrivateKey, PublicKey) {
        let private_key = PrivateKey::new(Scalar::random(&mut OsRng));
        let public_key = private_key.to_public_key();
        (private_key, public_key)
    }

    fn _generate_point(value: u64) -> RistrettoPoint {
        &Scalar::from(value) * &RISTRETTO_BASEPOINT_TABLE
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (private_key, public_key) = _generate_key_pair();

        let m = _generate_point(10);
        let c = public_key.encrypt_point(m);
        let m2 = private_key.decrypt_to_point(&c);
        assert_eq!(m, m2);
    }

    #[test]
    fn test_homomorphic_add() {
        let (private_key, public_key) = _generate_key_pair();

        let m1 = _generate_point(50);
        let m2 = _generate_point(100);

        let c1 = public_key.encrypt_point(m1);
        let c2 = public_key.encrypt_point(m2);
        let c3 = c1 + c2;

        let m3 = private_key.decrypt_to_point(&c3);
        assert_eq!(m1 + m2, m3);
    }

    #[test]
    fn test_homomorphic_add_plaintext() {
        let (private_key, public_key) = _generate_key_pair();

        let m1 = _generate_point(50);
        let m2 = _generate_point(100);

        // Enc(m1) + m2 = Enc(m1 + m2)
        let c1 = public_key.encrypt_point(m1);
        let c2 = c1 + m2;

        let m3 = private_key.decrypt_to_point(&c2);
        assert_eq!(m1 + m2, m3);
    }

    #[test]
    fn test_homomorphic_sub() {
        let (private_key, public_key) = _generate_key_pair();

        let m1 = _generate_point(50);
        let m2 = _generate_point(100);

        let c1 = public_key.encrypt_point(m1);
        let c2 = public_key.encrypt_point(m2);
        let c3 = c2 - c1;

        let m3 = private_key.decrypt_to_point(&c3);
        assert_eq!(m2 - m1, m3);
    }

    #[test]
    fn test_homomorphic_sub_plaintext() {
        let (private_key, public_key) = _generate_key_pair();

        let m1 = _generate_point(50);
        let m2 = _generate_point(100);

        // Enc(m1) + m2 = Enc(m1 + m2)
        let c1 = public_key.encrypt_point(m1);
        let c2 = c1 - m2;

        let m3 = private_key.decrypt_to_point(&c2);
        assert_eq!(m1 - m2, m3);
    }

    #[test]
    fn test_homomorphic_mul() {
        let (private_key, public_key) = _generate_key_pair();

        let m1 = _generate_point(50);
        let m2 = Scalar::from(100u64);

        let c1 = public_key.encrypt_point(m1);
        let c2 = c1 * m2;

        let m3 = private_key.decrypt_to_point(&c2);
        assert_eq!(m3, m1 * m2);
    }
}