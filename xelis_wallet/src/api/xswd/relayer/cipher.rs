use std::borrow::Cow;

use aes_gcm::{aead::Aead, KeyInit};
use thiserror::Error;

use crate::api::EncryptionMode;

enum CipherState {
    None,
    AES {
        cipher: aes_gcm::Aes256Gcm,
    },
    // Chacha20Poly1305 {
    //     cipher: chacha20poly1305::XChaCha20Poly1305,
    // },
}

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("invalid key")]
    InvalidKey,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("nonce overflow")]
    NonceOverflow,
}

pub struct Cipher {
    mode: CipherState,
    nonce: u64,
}

impl Cipher {
    pub fn new(mode: EncryptionMode) -> Result<Self, CipherError> {
        Ok(Self {
            mode: match mode {
                EncryptionMode::None => CipherState::None,
                EncryptionMode::AES { key } => {
                    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key)
                        .map_err(|_| CipherError::InvalidKey)?;
                    CipherState::AES { cipher }
                }
            },
            nonce: 0,
        })
    }

    pub fn encrypt<'a>(&mut self, data: &'a [u8]) -> Result<Cow<'a, [u8]>, CipherError> {
        Ok(match &self.mode {
            CipherState::None => Cow::Borrowed(data),
            CipherState::AES { cipher } => {
                let bytes = self.nonce.to_le_bytes();
                self.nonce = self.nonce.checked_add(1)
                    .ok_or(CipherError::NonceOverflow)?;

                let nonce = aes_gcm::Nonce::from_slice(&bytes);
                let encrypted_data = cipher.encrypt(nonce, data)
                    .map_err(|_| CipherError::EncryptionFailed)?;

                Cow::Owned(encrypted_data)
            }
        })
    }

    pub fn decrypt<'a>(&mut self, data: &'a [u8]) -> Result<Cow<'a, [u8]>, CipherError> {
        Ok(match &self.mode {
            CipherState::None => Cow::Borrowed(data),
            CipherState::AES { cipher } => {
                let bytes = self.nonce.to_le_bytes();
                self.nonce = self.nonce.checked_add(1)
                    .ok_or(CipherError::NonceOverflow)?;

                let nonce = aes_gcm::Nonce::from_slice(&bytes);
                let decrypted_data = cipher.decrypt(nonce, data)
                    .map_err(|_| CipherError::DecryptionFailed)?;

                Cow::Owned(decrypted_data)
            }
        })
    }
}