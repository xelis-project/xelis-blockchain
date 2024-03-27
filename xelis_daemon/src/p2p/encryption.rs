use std::sync::atomic::{AtomicBool, Ordering};

use chacha20poly1305::{aead::AeadMut, ChaCha20Poly1305, KeyInit};
use rand::rngs::OsRng;
use thiserror::Error;
use tokio::sync::Mutex;

// This symetric key is used to encrypt/decrypt the data
pub type EncryptionKey = [u8; 32];

// Each peer has its own key and can rotate as he want
// The nonce is incremented by one on each encrypt/decrypt
// This allows us to not send the generated nonce and reduce bandwidth usage
// Using a 64 bits nonce is enough for our use case
// We use the first 8 bytes to store the nonce and the last 4 bytes are set to 0
// Also, we rotate the keys every 1 GB of data to avoid any potential attack
// We would reach 1 GB much before the nonce overflow
// This is a simple implementation and we can improve it later

struct CipherState {
    cipher: ChaCha20Poly1305,
    nonce: u64,
    nonce_buffer: [u8; 12],
}

pub struct Encryption {
    // Cipher using our key to encrypt packets
    our_cipher: Mutex<Option<CipherState>>,
    // Cipher using the peer key to decrypt packets
    peer_cipher: Mutex<Option<CipherState>>,
    // This flag helps us to know if the encryption is ready
    // In case we want to use it before the handshake is done
    ready: AtomicBool,
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
            our_cipher: Mutex::new(None),
            peer_cipher: Mutex::new(None),
            ready: AtomicBool::new(false),
        }
    }

    // Mark has ready because
    pub fn mark_as_ready(&self) {
        self.ready.store(true, Ordering::SeqCst);
    }

    // Check if the encryption is ready to write (encrypt)
    pub async fn is_write_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst) && self.our_cipher.lock().await.is_some()
    }

    // Check if the encryption is ready to read (decrypt)
    pub async fn is_read_ready(&self) -> bool {
        self.peer_cipher.lock().await.is_some()
    }

    // Generate a new random key
    pub fn generate_key(&self) -> EncryptionKey {
        ChaCha20Poly1305::generate_key(&mut OsRng).into()
    }

    // Encrypt a packet using the shared symetric key
    pub async fn encrypt_packet(&self, input: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let mut lock = self.our_cipher.lock().await;
        let cipher_state = lock.as_mut().ok_or(EncryptionError::WriteNotReady)?;

        // fill our buffer
        cipher_state.nonce_buffer[0..8].copy_from_slice(&cipher_state.nonce.to_be_bytes());

        // Encrypt the packet
        let res = cipher_state.cipher.encrypt(&cipher_state.nonce_buffer.into(), input)
            .map_err(|_| EncryptionError::CipherError)?;

        // Increment the nonce so we don't use the same nonce twice
        cipher_state.nonce += 1;

        Ok(res)
    }

    // Decrypt a packet using the shared symetric key
    pub async fn decrypt_packet(&self, buf: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let mut lock = self.peer_cipher.lock().await;
        let cipher_state = lock.as_mut().ok_or(EncryptionError::WriteNotReady)?;

        // fill our buffer
        cipher_state.nonce_buffer[0..8].copy_from_slice(&cipher_state.nonce.to_be_bytes());

        // Decrypt packet
        let res = cipher_state.cipher.decrypt(&cipher_state.nonce_buffer.into(), buf.as_ref())
            .map_err(|_| EncryptionError::CipherError)?;

        // Increment the nonce so we don't use the same nonce twice
        cipher_state.nonce += 1;

        Ok(res)
    }

    fn create_or_update_state(state: &mut Option<CipherState>, key: EncryptionKey) -> Result<(), EncryptionError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| EncryptionError::InvalidKey)?;
        if let Some(cipher_state) = state.as_mut() {
            cipher_state.cipher = cipher;
            cipher_state.nonce = 0;
        } else {
            *state = Some(CipherState {
                nonce_buffer: [0; 12],
                cipher,
                nonce: 0
            });
        }
        Ok(())
    }

    // Rotate the key with a new one
    pub async fn rotate_key(&self, new_key: EncryptionKey, our: bool) -> Result<(), EncryptionError> {
        if our {
            let mut lock = self.our_cipher.lock().await;
            Self::create_or_update_state(&mut lock, new_key)?;
        } else {
            let mut lock = self.peer_cipher.lock().await;
            Self::create_or_update_state(&mut lock, new_key)?;
        }

        Ok(())
    }
}