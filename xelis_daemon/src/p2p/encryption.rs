use chacha20poly1305::{
    aead::{
        rand_core::OsError,
        AeadInOut,
        Buffer
    },
    ChaCha20Poly1305,
    KeyInit
};
use thiserror::Error;
use xelis_common::tokio::sync::Mutex;
use log::trace;

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

// Encryption struct to handle encryption/decryption of packets
// It uses ChaCha20-Poly1305 AEAD cipher for encryption/decryption
// It also uses Snappy compression to compress/decompress packets if enabled
pub struct Encryption {
    // Cipher using our key to encrypt packets
    our_cipher: Mutex<Option<CipherState>>,
    // Cipher using the peer key to decrypt packets
    peer_cipher: Mutex<Option<CipherState>>,
    // Is encryption mode ready
    ready: bool,
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
    #[error("Cipher error: encrypt")]
    EncryptError,
    #[error("Cipher error: decrypt")]
    DecryptError,
    #[error("Not supported")]
    NotSupported,
    #[error(transparent)]
    RngError(#[from] OsError)
}

impl Encryption {
    #[inline]
    pub fn new() -> Self {
        Self {
            our_cipher: Mutex::new(None),
            peer_cipher: Mutex::new(None),
            ready: false,
        }
    }

    // Enable encryption
    #[inline]
    pub fn mark_ready(&mut self) {
        self.ready = true;
    }

    // Is encryption mode ready
    #[inline]
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
    pub fn generate_key(&self) -> Result<EncryptionKey, EncryptionError> {
        ChaCha20Poly1305::generate_key()
            .map(Into::into)
            .map_err(EncryptionError::from)
    }

    // Encrypt a packet using the shared symetric key
    pub async fn encrypt_packet(&self, input: &mut impl Buffer) -> Result<(), EncryptionError> {
        trace!("Encrypting packet with length {}", input.len());
        let mut lock = self.our_cipher.lock().await;
        trace!("our cipher locked");

        let cipher_state = lock.as_mut()
            .ok_or(EncryptionError::WriteNotReady)?;

        // fill our buffer
        cipher_state.nonce_buffer[0..8].copy_from_slice(&cipher_state.nonce.to_be_bytes());

        // Encrypt the packet
        cipher_state.cipher.encrypt_in_place(&cipher_state.nonce_buffer.into(), &[], input)
            .map_err(|_| EncryptionError::EncryptError)?;

        // Increment the nonce so we don't use the same nonce twice
        cipher_state.nonce += 1;

        Ok(())
    }

    // Decrypt a packet using the shared symetric key
    pub async fn decrypt_packet(&self, buf: &mut impl Buffer) -> Result<(), EncryptionError> {
        trace!("Decrypting packet with length {}", buf.len());
        let mut lock = self.peer_cipher.lock().await;
        trace!("peer cipher locked");

        let cipher_state = lock.as_mut()
            .ok_or(EncryptionError::ReadNotReady)?;

        // fill our buffer
        cipher_state.nonce_buffer[0..8].copy_from_slice(&cipher_state.nonce.to_be_bytes());

        // Decrypt packet
        cipher_state.cipher.decrypt_in_place(&cipher_state.nonce_buffer.into(), &[], buf)
            .map_err(|_| EncryptionError::DecryptError)?;

        // Increment the nonce so we don't use the same nonce twice
        cipher_state.nonce += 1;

        trace!("Packet decrypted with length {}", buf.len());

        Ok(())
    }

    fn create_or_update_state(state: &mut Option<CipherState>, key: EncryptionKey) -> Result<(), EncryptionError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| EncryptionError::InvalidKey)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use rand::RngCore;

    #[tokio::test]
    async fn test_encryption_decryption() {
        let encryption = Encryption::new();

        let key = encryption.generate_key().unwrap();
        encryption.rotate_key(key, CipherSide::Both).await.unwrap();

        let mut data = BytesMut::from(&b"Hello, world!"[..]);

        encryption.encrypt_packet(&mut data).await.unwrap();
        encryption.decrypt_packet(&mut data).await.unwrap();

        assert_eq!(&data[..], b"Hello, world!");
    }

    #[tokio::test]
    async fn test_encryption_decryption_large_data() {
        let encryption = Encryption::new();

        let key = encryption.generate_key().unwrap();
        encryption.rotate_key(key, CipherSide::Both).await.unwrap();

        // Create a large random data buffer
        let mut rng = rand::thread_rng();
        let mut original_data = vec![0u8; 10 * 1024]; // 10 KB of random data
        rng.fill_bytes(&mut original_data);

        let mut data = BytesMut::from(&original_data[..]);

        encryption.encrypt_packet(&mut data).await.unwrap();
        encryption.decrypt_packet(&mut data).await.unwrap();

        assert_eq!(&data[..], &original_data[..]);
    }
}