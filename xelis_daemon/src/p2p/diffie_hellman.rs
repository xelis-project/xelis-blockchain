use std::{fmt, str::FromStr};

use serde::{Serialize, Deserialize};
pub use x25519_dalek::{PublicKey, StaticSecret};
use rand::rngs::OsRng;

/// A wrapped secret key
/// For clap implementation
#[derive(Clone)]
pub struct WrappedSecret(StaticSecret);

impl fmt::Debug for WrappedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WrappedSecret")
    }
}

impl From<WrappedSecret> for StaticSecret {
    fn from(wrapped: WrappedSecret) -> Self {
        wrapped.0
    }
}

impl From<StaticSecret> for WrappedSecret {
    fn from(secret: StaticSecret) -> Self {
        Self(secret)
    }
}

impl From<WrappedSecret> for DHKeyPair {
    fn from(wrapped: WrappedSecret) -> Self {
        DHKeyPair::from(wrapped.0)
    }
}

/// The action to take when a key is different from the one stored locally
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerificationAction {
    /// Warn the user by logging a message
    Warn,
    /// Reject the connection with the peer
    Reject,
    /// Ignore the key change for the peer
    Ignore
}

impl Default for KeyVerificationAction {
    fn default() -> Self {
        Self::Ignore
    }
}

/// A Diffie-Hellman keypair
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
    #[inline]
    pub fn get_public_key(&self) -> &PublicKey {
        &self.pub_key
    }

    /// Get the shared secret between this keypair and another public key
    #[inline]
    pub fn get_shared_secret(&self, pub_key: &PublicKey) -> [u8; 32] {
        self.priv_key.diffie_hellman(pub_key).to_bytes()
    }
}

impl FromStr for WrappedSecret {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded: [u8; 32] = hex::decode(s)
            .map_err(|_| "Invalid hex")?
            .try_into()
            .map_err(|_| "Invalid decoded size")?;

        let priv_key = StaticSecret::from(decoded);
        Ok(Self(priv_key))
    }
}

impl serde::Serialize for WrappedSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0.to_bytes()))
    }
}

impl<'a> serde::Deserialize<'a> for WrappedSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>
    {
        let s = String::deserialize(deserializer)?;
        WrappedSecret::from_str(&s).map_err(serde::de::Error::custom)
    }
}