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
    // Is encryption mode ready
    ready: bool
}

pub enum CipherSide {
    Our,
    Peer,
    Both
}

impl CipherSide {
    pub fn is_our(&self) -> bool {
        matches!(self, Self::Our | Self::Both)
    }

    pub fn is_peer(&self) -> bool {
        matches!(self, Self::Peer | Self::Both)
    }
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
            ready: false
        }
    }

    // Enable encryption
    pub fn mark_ready(&mut self) {
        self.ready = true;
    }

    // Is encryption mode ready
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    // Check if the encryption is ready to read (decrypt)
    pub async fn is_read_ready(&self) -> bool {
        self.peer_cipher.lock().await.is_some()
    }

    // Check if the encryption is ready to write (encrypt)
    pub async fn is_write_ready(&self) -> bool {
        self.our_cipher.lock().await.is_some()
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
        let cipher_state = lock.as_mut().ok_or(EncryptionError::ReadNotReady)?;

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
    pub async fn rotate_key(&self, new_key: EncryptionKey, side: CipherSide) -> Result<(), EncryptionError> {
        if side.is_our() {
            let mut lock = self.our_cipher.lock().await;
            Self::create_or_update_state(&mut lock, new_key)?;
        }

        if side.is_peer() {
            let mut lock = self.peer_cipher.lock().await;
            Self::create_or_update_state(&mut lock, new_key)?;
        }

        Ok(())
    }
}