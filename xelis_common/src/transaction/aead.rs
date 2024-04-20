use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadInPlace, ChaCha20Poly1305, KeyInit,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use sha3::Digest;
use zeroize::Zeroize;
use thiserror::Error;

use crate::{
    crypto::elgamal::{
        Ciphertext,
        DecryptHandle,
        PedersenOpening,
        PrivateKey,
        H
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};

pub type AEADKey = chacha20poly1305::Key;
pub type KDF = sha3::Sha3_256;

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

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Zeroize)]
pub struct PlaintextData(pub Vec<u8>);

/// See [`derive_aead_key`].
pub fn derive_aead_key_from_opening(opening: &PedersenOpening) -> AEADKey {
    derive_aead_key(&(opening.as_scalar() * &*H).compress())
}
/// See [`derive_aead_key`].
pub fn derive_aead_key_from_ct(
    sk: &PrivateKey,
    ciphertext: &Ciphertext,
) -> AEADKey {
    derive_aead_key_from_handle(sk, ciphertext.handle())
}

/// See [`derive_aead_key`].
pub fn derive_aead_key_from_handle(
    sk: &PrivateKey,
    handle: &DecryptHandle,
) -> AEADKey {
    derive_aead_key(&(sk.as_scalar() * handle.as_point()).compress())
}

/// During encryption, we know the opening `r`, so this needs to be called with `r * H`.
/// During decryption, we don't have to find `r`, we can just use `s * D` which is equal to `r * H` with our ciphertext.
pub fn derive_aead_key(point: &CompressedRistretto) -> AEADKey {
    let mut hash = KDF::new();
    hash.update(point.as_bytes());
    hash.finalize()
}

impl AEADCipher {
    /// Warning: keys should not be reused
    pub fn decrypt_in_place(mut self, key: &AEADKey) -> Result<PlaintextData, CipherFormatError> {
        let c = ChaCha20Poly1305::new(&key);
        c.decrypt_in_place(NONCE.into(), &[], &mut self.0)
            .map_err(|_| CipherFormatError)?;

        Ok(PlaintextData(self.0))
    }

    /// Warning: keys should not be reused
    pub fn decrypt(&self, key: &AEADKey) -> Result<PlaintextData, CipherFormatError> {
        let c = ChaCha20Poly1305::new(&key);
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
    pub fn encrypt_in_place(mut self, key: &AEADKey) -> AEADCipher {
        let c = ChaCha20Poly1305::new(&key);
        c.encrypt_in_place(NONCE.into(), &[], &mut self.0)
            .expect("unreachable (unsufficient capacity on a vec)");

        AEADCipher(self.0)
    }
}

impl Serializer for AEADCipher {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(AEADCipher(Vec::read(reader)?))
    }
}