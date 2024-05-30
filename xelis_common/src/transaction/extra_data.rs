use std::borrow::Cow;

use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadInPlace, ChaCha20Poly1305, KeyInit,
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
    api::DataElement,
    crypto::elgamal::{
        Ciphertext,
        CompressedHandle,
        DecryptHandle,
        PedersenOpening,
        PrivateKey,
        PublicKey,
        H,
        RISTRETTO_COMPRESSED_SIZE
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};

use super::Role;

pub type SharedKey = chacha20poly1305::Key;
pub type KDF = sha3::Sha3_256;

// The size of the tag in bytes.
pub const TAG_SIZE: usize = 16;

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

// A wrapper around a Vec<u8>.
// This is used for outside the wallet as we don't know what is used
// Cipher format isn't validated
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct UnknownExtraDataFormat(pub Vec<u8>);

// New version of Extra Data due to the issue of commitment randomness reuse
// https://gist.github.com/kayabaNerve/b754e9ed9fa4cc2c607f38a83aa3df2a
// We create a new opening to be independant of the amount opening.
// This is more secure and prevent bruteforce attack from the above link.
// We need to store 64 bytes more than previous version due to the exclusive handles created.
pub struct ExtraData {
    cipher: Cipher,
    sender_handle: CompressedHandle,
    receiver_handle: CompressedHandle,
}

impl UnknownExtraDataFormat {
    pub fn decrypt_v2(&self, private_key: &PrivateKey, role: Role) -> Result<DataElement, CipherFormatError> {
        let e = ExtraData::from_bytes(&self.0).map_err(|_| CipherFormatError)?;
        let plaintext = e.decrypt(private_key, role)?;
        DataElement::from_bytes(&plaintext.0).map_err(|_| CipherFormatError)
    }

    pub fn decrypt_v1(&self, private_key: &PrivateKey, handle: &DecryptHandle) -> Result<DataElement, CipherFormatError> {
        let key = derive_shared_key_from_handle(private_key, handle);
        let plaintext = AEADCipherInner(Cow::Borrowed(&self.0)).decrypt(&key)?;
        DataElement::from_bytes(&plaintext.0).map_err(|_| CipherFormatError)
    }

    pub fn decrypt(&self, private_key: &PrivateKey, handle: &DecryptHandle, role: Role) -> Result<DataElement, CipherFormatError> {
        // Try the new version
        // If it has 64 + 2 bytes of overhead at least, it may be a V2 
        if self.0.len() >= (RISTRETTO_COMPRESSED_SIZE * 2) + 2 {
            if let Ok(e) = self.decrypt_v2(private_key, role) {
                return Ok(e)
            }
        }

        // Otherwise, fallback on old version
        self.decrypt_v1(private_key, handle)
    }
}

impl ExtraData {
    // Create a new extra data that will encrypt the message for receiver & sender keys.
    // Both will be able to decrypt it.
    pub fn new(data: PlaintextData, sender: &PublicKey, receiver: &PublicKey) -> Self {
        // Generate a new opening (randomness r)
        let opening = PedersenOpening::generate_new();
        // From the randomness, derive the opening it to get the shared key
        // that will be used for encrypt/decrypt
        let k = derive_shared_key_from_opening(&opening);
        Self {
            // Encrypt the cipher using the shared key
            cipher: data.encrypt_in_place(&k),
            // Create a handle for the sender so he can decrypt the message later
            // SH = sender PK * r
            // Because SK is invert of PK, we can decrypt it by doing SH * SK 
            sender_handle: sender.decrypt_handle(&opening).compress(),
            // Same for the receiver
            // RH = receiver PK * r
            receiver_handle: receiver.decrypt_handle(&opening).compress(),
        }
    }

    // Estimate the final size for the extra data based on the plaintext format
    pub fn estimate_size(data: &DataElement) -> usize {
        let cipher = Cipher(data.to_bytes());
        cipher.size() + (RISTRETTO_COMPRESSED_SIZE * 2)
    }

    // Get the compressed handle based on its role
    fn get_handle(&self, role: Role) -> &CompressedHandle {
        match role {
            Role::Sender => &self.sender_handle,
            Role::Receiver => &self.receiver_handle,
        }
    }

    // Decrypt the message using the private key and the role to determine the correct handle to use.
    pub fn decrypt(&self, private_key: &PrivateKey, role: Role) -> Result<PlaintextData, CipherFormatError> {
        let handle = self.get_handle(role).decompress().map_err(|_| CipherFormatError)?;
        let key = derive_shared_key_from_handle(private_key, &handle);
        Ok(self.cipher.clone().decrypt(&key)?)
    }
}

pub enum ExtraDataVariant {
    // Warning: should not be used anymore as cryptographically broken
    V1(AEADCipher),
    V2(ExtraData)
}

impl Serializer for ExtraData {
    fn write(&self, writer: &mut Writer) {
        self.sender_handle.write(writer); 
        self.receiver_handle.write(writer);
        self.cipher.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self {
            sender_handle: CompressedHandle::read(reader)?,
            receiver_handle: CompressedHandle::read(reader)?,
            cipher: Cipher::read(reader)?,
        })
    }

    fn size(&self) -> usize {
        self.cipher.size() + self.sender_handle.size() + self.receiver_handle.size()
    }
}

/// See [`derive_shared_key`].
pub fn derive_shared_key_from_opening(opening: &PedersenOpening) -> SharedKey {
    derive_shared_key(&(opening.as_scalar() * &*H).compress())
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
    hash.finalize()
}

impl AEADCipher {
    /// Warning: keys should not be reused
    pub fn decrypt_in_place(mut self, key: &SharedKey) -> Result<PlaintextData, CipherFormatError> {
        let c = ChaCha20Poly1305::new(&key);
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
        let mut c = ChaCha20::new(key.into(), NONCE.into());
        c.try_apply_keystream(&mut self.0)
            .map_err(|_| CipherFormatError)?;

        Ok(PlaintextData(self.0))
    }
}

impl From<AEADCipher> for UnknownExtraDataFormat {
    fn from(value: AEADCipher) -> Self {
        Self(value.0)
    }
}

impl From<Cipher> for UnknownExtraDataFormat {
    fn from(value: Cipher) -> Self {
        Self(value.0)
    }
}

impl From<ExtraData> for UnknownExtraDataFormat {
    fn from(value: ExtraData) -> Self {
        Self(value.to_bytes())
    }
}

impl<'a> AEADCipherInner<'a> {
    /// Warning: keys should not be reused
    pub fn decrypt(&self, key: &SharedKey) -> Result<PlaintextData, CipherFormatError> {
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
    pub fn encrypt_in_place_with_aead(mut self, key: &SharedKey) -> AEADCipher {
        let c = ChaCha20Poly1305::new(&key);
        c.encrypt_in_place(NONCE.into(), &[], &mut self.0)
            .expect("unreachable (unsufficient capacity on a vec)");

        AEADCipher(self.0)
    }

    /// Warning: keys should not be reused
    pub fn encrypt_in_place(mut self, key: &SharedKey) -> Cipher {
        let mut c = ChaCha20::new(key.into(), NONCE.into());
        c.apply_keystream(&mut self.0);

        Cipher(self.0)
    }
}

impl Serializer for UnknownExtraDataFormat {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self(Vec::read(reader)?))
    }

    fn size(&self) -> usize {
        // 2 represents the u16 size of the vector
        2 + self.0.len()
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
        // 2 represents the u16 size of the vector
        2 + self.0.len()
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
        // 2 represents the u16 size of the vector
        2 + self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;

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
}