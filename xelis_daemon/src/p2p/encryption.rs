use chacha20poly1305::{aead::AeadMut, ChaCha20Poly1305, KeyInit};
use rand::rngs::OsRng;
use thiserror::Error;

// This symetric key is used to encrypt/decrypt the data
pub type EncryptionKey = [u8; 32];

// Each peer has its own key and can rotate as he want
// The nonce is incremented by one on each encrypt/decrypt
// This allows us to not send the generated nonce and reduce bandwidth usage
pub struct Encryption {
    nonce_buffer: [u8; 12],
    // This is the symetric key used to encrypt the data
    our_cipher: Option<ChaCha20Poly1305>,
    // Key used by the peer
    peer_cipher: Option<ChaCha20Poly1305>,
    // Nonce to use for the next outgoing packet
    our_nonce: u64,
    // Nonce to expect for the next incoming packet
    peer_nonce: u64
}

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption write mode is not ready")]
    WriteNotReady,
    #[error("Encryption read mode is not ready")]
    ReadNotReady,
    #[error("Encryption is ready")]
    Ready,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Cipher error")]
    CipherError,
    #[error("Not supported")]
    NotSupported,
}

impl Encryption {
    pub fn new() -> Self {
        Self {
            nonce_buffer: [0; 12],
            our_cipher: None,
            peer_cipher: None,
            our_nonce: 0,
            peer_nonce: 0
        }
    }

    // Check if the encryption is ready to write (encrypt)
    pub fn is_write_ready(&self) -> bool {
        self.our_cipher.is_some()
    }

    // Check if the encryption is ready to read (decrypt)
    pub fn is_read_ready(&self) -> bool {
        self.peer_cipher.is_some()
    }

    // Generate a new random key
    pub fn generate_key(&self) -> EncryptionKey {
        ChaCha20Poly1305::generate_key(&mut OsRng).into()
    }

    // Encrypt a packet using the shared symetric key
    pub fn encrypt_packet(&mut self, input: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let cipher = self.our_cipher.as_mut().ok_or(EncryptionError::WriteNotReady)?;

        // fill our buffer
        self.nonce_buffer[0..8].copy_from_slice(&self.our_nonce.to_be_bytes());

        let nonce_part: &[u8; 12] = self.nonce_buffer[0..12].try_into()
            .map_err(|_| EncryptionError::InvalidNonce)?;

        // Encrypt the packet
        let res = cipher.encrypt(nonce_part.into(), input)
            .map_err(|_| EncryptionError::CipherError)?;

        // Increment the nonce so we don't use the same nonce twice
        self.our_nonce += 1;

        Ok(res)
    }

    // Decrypt a packet using the shared symetric key
    pub fn decrypt_packet(&mut self, buf: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let cipher = self.peer_cipher.as_mut().ok_or(EncryptionError::ReadNotReady)?;

        // fill our buffer
        self.nonce_buffer[0..8].copy_from_slice(&self.peer_nonce.to_be_bytes());

        let nonce_part: &[u8; 12] = self.nonce_buffer[0..12].try_into()
            .map_err(|_| EncryptionError::InvalidNonce)?;

        // Decrypt packet
        let res = cipher.decrypt(nonce_part.into(), buf.as_ref())
            .map_err(|_| EncryptionError::CipherError)?;

        // Increment the nonce so we don't use the same nonce twice
        self.peer_nonce += 1;

        Ok(res)
    }

    // Rotate the key with a new one
    pub fn rotate_key(&mut self, new_key: EncryptionKey, our: bool) -> Result<(), EncryptionError> {
        let cipher = Some(ChaCha20Poly1305::new_from_slice(&new_key).map_err(|_| EncryptionError::InvalidKey)?);
        if our {
            self.our_cipher = cipher;
            self.our_nonce = 0;
        } else {
            self.peer_cipher = cipher;
            self.peer_nonce = 0;
        }
        Ok(())
    }
}