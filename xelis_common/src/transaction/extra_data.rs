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
        CompressedHandle,
        DecryptHandle,
        PedersenOpening,
        PrivateKey,
        PublicKey,
        H
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
};

use super::Role;

pub type AEADKey = chacha20poly1305::Key;
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

// A wrapper around a Vec<u8>.
// Inner data is not checked, so everything can be set as data to encrypt.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Zeroize)]
pub struct PlaintextData(pub Vec<u8>);

// New version of Extra Data due to the issue of commitment randomness reuse
// https://gist.github.com/kayabaNerve/b754e9ed9fa4cc2c607f38a83aa3df2a
// We create a new opening to be independant of the amount opening.
// This is more secure and prevent bruteforce attack from the above link.
// We need to store 64 bytes more than previous version due to the exclusive handles created.
pub struct ExtraData {
    cipher: AEADCipher,
    sender_handle: CompressedHandle,
    receiver_handle: CompressedHandle,
}

impl ExtraData {
    // Create a new extra data that will encrypt the message for receiver & sender keys.
    // Both will be able to decrypt it.
    pub fn new(data: PlaintextData, sender: &PublicKey, receiver: &PublicKey) -> Self {
        let opening = PedersenOpening::generate_new();
        let k = derive_aead_key_from_opening(&opening);
        Self {
            cipher: data.encrypt_in_place(&k),
            sender_handle: sender.decrypt_handle(&opening).compress(),
            receiver_handle: receiver.decrypt_handle(&opening).compress(),
        }
    }

    // Get the compressed handle based on its role
    fn get_handle(&self, role: Role) -> &CompressedHandle {
        match role {
            Role::Sender => &self.sender_handle,
            Role::Receiver => &self.receiver_handle,
        }
    }

    // Decrypt in place the message using the private key and the role to determine the correct handle to use.
    pub fn decrypt_in_place(self, private_key: &PrivateKey, role: Role) -> Result<PlaintextData, CipherFormatError> {
        let handle = self.get_handle(role).decompress().map_err(|_| CipherFormatError)?;
        let key = derive_aead_key_from_handle(private_key, &handle);
        Ok(self.cipher.decrypt_in_place(&key)?)
    }

    // Decrypt the message using the private key and the role to determine the correct handle to use.
    pub fn decrypt(&self, private_key: &PrivateKey, role: Role) -> Result<PlaintextData, CipherFormatError> {
        let handle = self.get_handle(role).decompress().map_err(|_| CipherFormatError)?;
        let key = derive_aead_key_from_handle(private_key, &handle);
        Ok(self.cipher.decrypt(&key)?)
    }
}

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

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let opening = PedersenOpening::generate_new();
        let k = derive_aead_key_from_opening(&opening);
        let bytes = vec![1, 2, 3, 4, 5];
        let data = PlaintextData(bytes.clone());
        let cipher = data.encrypt_in_place(&k);
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