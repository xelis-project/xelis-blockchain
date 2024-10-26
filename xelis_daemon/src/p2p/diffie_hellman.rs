pub use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

pub struct DHKeyPair {
    pub_key: PublicKey,
    priv_key: StaticSecret
}

impl DHKeyPair {
    /// Create a new keypair
    pub fn new() -> Self {
        let priv_key = StaticSecret::random_from_rng(&mut OsRng);
        let pub_key = PublicKey::from(&priv_key);
        Self {
            pub_key,
            priv_key
        }
    }

    /// Create a keypair from a private key
    pub fn from(priv_key: StaticSecret) -> Self {
        let pub_key = PublicKey::from(&priv_key);
        Self {
            pub_key,
            priv_key
        }
    }

    /// Get the public key of this keypair
    pub fn get_public_key(&self) -> &PublicKey {
        &self.pub_key
    }

    /// Get the shared secret between this keypair and another public key
    pub fn get_shared_secret(&self, pub_key: &PublicKey) -> [u8; 32] {
        self.priv_key.diffie_hellman(pub_key).to_bytes()
    }
}