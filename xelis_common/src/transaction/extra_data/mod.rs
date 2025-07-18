mod plaintext;
mod shared_key;
mod unknown;
mod extra_data;
mod typed;

use std::borrow::Cow;

use chacha20poly1305::{
    aead::{Aead, Payload, AeadInOut},
    ChaCha20Poly1305,
    KeyInit,
};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use sha3::Digest;
use zeroize::Zeroize;
use thiserror::Error;

use crate::{
    crypto::{
        elgamal::{
            Ciphertext,
            DecryptHandle,
            PedersenOpening,
            PrivateKey,
        },
        proofs::H
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};

pub use plaintext::{PlaintextExtraData, PlaintextFlag};
pub use shared_key::SharedKey;
pub use unknown::UnknownExtraDataFormat;
pub use extra_data::ExtraData;
pub use typed::ExtraDataType;

// Key Derivation Function used to derive the shared key
type KDF = sha3::Sha3_256;

// This error is thrown when the ciphertext is not in the expected format.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[error("malformated ciphertext")]
pub struct CipherFormatError;

/// Every transfer has its associated secret key, derived from the shared secret.
/// We never use a key twice, then. We can reuse the same nonce everytime.
const NONCE: &[u8; 12] = b"xelis-crypto";

/// This is the encrypted data, which is the result of the encryption process.
/// It is a simple wrapper around a vector of bytes.
/// This doesn't contain the nonce, which is always the same.
/// Cipher format isn't validated, it is assumed to be correct.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AEADCipher(pub Vec<u8>);

// Encrypted data with no AEAD tag set.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Cipher(pub Vec<u8>);

// Internal struct used for decrypt process
struct AEADCipherInner<'a>(Cow<'a, Vec<u8>>);

// A wrapper around a Vec<u8>.
// Inner data is not checked, so everything can be set as data to encrypt.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Zeroize)]
pub struct PlaintextData(pub Vec<u8>);

/// See [`derive_shared_key`].
pub fn derive_shared_key_from_opening(opening: &PedersenOpening) -> SharedKey {
    derive_shared_key(&(opening.as_scalar() * (*H)).compress())
}

/// See [`derive_shared_key`].
pub fn derive_shared_key_from_ct(
    sk: &PrivateKey,
    ciphertext: &Ciphertext,
) -> SharedKey {
    derive_shared_key_from_handle(sk, ciphertext.handle())
}

/// See [`derive_shared_key`].
pub fn derive_shared_key_from_handle(
    sk: &PrivateKey,
    handle: &DecryptHandle,
) -> SharedKey {
    derive_shared_key(&(sk.as_scalar() * handle.as_point()).compress())
}

/// During encryption, we know the opening `r`, so this needs to be called with `r * H`.
/// During decryption, we don't have to find `r`, we can just use `s * D` which is equal to `r * H` with our ciphertext.
pub fn derive_shared_key(point: &CompressedRistretto) -> SharedKey {
    let mut hash = KDF::new();
    hash.update(point.as_bytes());
    let bytes: [u8; 32] = hash.finalize().into();
    SharedKey(bytes)
}

impl AEADCipher {
    /// Warning: keys should not be reused
    pub fn decrypt_in_place(mut self, key: &SharedKey) -> Result<PlaintextData, CipherFormatError> {
        let c = ChaCha20Poly1305::new(&key.0.into());
        c.decrypt_in_place(NONCE.into(), &[], &mut self.0)
            .map_err(|_| CipherFormatError)?;

        Ok(PlaintextData(self.0))
    }

    /// Warning: keys should not be reused
    pub fn decrypt(&self, key: &SharedKey) -> Result<PlaintextData, CipherFormatError> {
        AEADCipherInner(Cow::Borrowed(&self.0)).decrypt(key)
    }
}

impl Cipher {
    /// Warning: keys should not be reused
    pub fn decrypt(mut self, key: &SharedKey) -> Result<PlaintextData, CipherFormatError> {
        let mut c = ChaCha20::new(&key.0.into(), NONCE.into());
        c.try_apply_keystream(&mut self.0)
            .map_err(|_| CipherFormatError)?;

        Ok(PlaintextData(self.0))
    }
}

impl<'a> AEADCipherInner<'a> {
    /// Warning: keys should not be reused
    pub fn decrypt(&self, key: &SharedKey) -> Result<PlaintextData, CipherFormatError> {
        let c = ChaCha20Poly1305::new(&key.0.into());
        let res = c.decrypt(
            NONCE.into(),
            Payload {
                msg: &self.0,
                aad: &[],
            },
        )
        .map_err(|_| CipherFormatError)?;

        Ok(PlaintextData(res))
    }
}

impl PlaintextData {
    /// Warning: keys should not be reused
    pub fn encrypt_in_place_with_aead(mut self, key: &SharedKey) -> AEADCipher {
        let c = ChaCha20Poly1305::new(&key.0.into());
        c.encrypt_in_place(NONCE.into(), &[], &mut self.0)
            .expect("unreachable (unsufficient capacity on a vec)");

        AEADCipher(self.0)
    }

    /// Warning: keys should not be reused
    pub fn encrypt_in_place(mut self, key: &SharedKey) -> Cipher {
        let mut c = ChaCha20::new(&key.0.into(), NONCE.into());
        c.apply_keystream(&mut self.0);

        Cipher(self.0)
    }
}

impl Serializer for AEADCipher {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self(Vec::read(reader)?))
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

impl Serializer for Cipher {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self(Vec::read(reader)?))
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::KeyPair,
        transaction::Role
    };

    use super::*;

    #[test]
    fn test_encrypt_decrypt_v1() {
        let opening = PedersenOpening::generate_new();
        let k = derive_shared_key_from_opening(&opening);
        let bytes = vec![1, 2, 3, 4, 5];
        let data = PlaintextData(bytes.clone());
        let cipher = data.encrypt_in_place_with_aead(&k);
        let decrypted = cipher.decrypt_in_place(&k).unwrap();
        assert_eq!(decrypted.0, bytes);
    }

    #[test]
    fn test_encrypt_decrypt_extra_data() {
        let alice = KeyPair::new();
        let bob = KeyPair::new();

        let bytes = vec![1, 2, 3, 4, 5];
        let data = PlaintextData(bytes.clone());
        let extra_data = ExtraData::new(data, alice.get_public_key(), bob.get_public_key());

        // Decrypt for alice
        let decrypted = extra_data.decrypt(alice.get_private_key(), Role::Sender).unwrap();
        assert_eq!(decrypted.0, bytes);

        // Decrypt for bob
        let decrypted = extra_data.decrypt(bob.get_private_key(), Role::Receiver).unwrap();
        assert_eq!(decrypted.0, bytes);
    }

    #[test]
    fn test_estimate_extra_data_size() {
        let alice = KeyPair::new();
        let bob = KeyPair::new();

        let data = 1234567890u64.into();
        let size = ExtraData::estimate_size(&data);
        let encrypted = ExtraData::new(PlaintextData(data.to_bytes()), alice.get_public_key(), bob.get_public_key()).to_bytes();
        assert_eq!(size, encrypted.size());
    }
}