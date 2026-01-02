use std::borrow::Cow;

use aes_gcm::{KeyInit, aead::{Aead, Nonce}};
use rand::Rng;
use thiserror::Error;

use crate::api::EncryptionMode;

enum CipherState {
    None,
    AES {
        cipher: aes_gcm::Aes256Gcm,
    },
    Chacha20Poly1305 {
        cipher: chacha20poly1305::ChaCha20Poly1305,
    },
}

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("invalid key")]
    InvalidKey,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("random generation error")]
    Rng,
}

pub struct Cipher {
    mode: CipherState,
}

impl Cipher {
    #[inline(always)]
    fn new_internal<T: KeyInit>(key: &[u8]) -> Result<T, CipherError> {
        T::new_from_slice(key).map_err(|_| CipherError::InvalidKey)
    }

    pub fn new(mode: Option<EncryptionMode>) -> Result<Self, CipherError> {
        Ok(Self {
            mode: match mode {
                None => CipherState::None,
                Some(EncryptionMode::AES { key }) => CipherState::AES { cipher: Self::new_internal(&key)? },
                Some(EncryptionMode::Chacha20Poly1305 { key }) => CipherState::Chacha20Poly1305 { cipher: Self::new_internal(&key)? },
            },
        })
    }

    fn encrypt_internal<'a, T: Aead>(data: &'a [u8], cipher: &T) -> Result<Cow<'a, [u8]>, CipherError> {
        let mut nonce = Nonce::<T>::default();
        rand::thread_rng()
            .try_fill(nonce.as_mut_slice())
            .map_err(|_| CipherError::Rng)?;

        let encrypted_data = cipher.encrypt(&nonce, data)
            .map_err(|_| CipherError::EncryptionFailed)?;

        // Prepend nonce to the encrypted data
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&encrypted_data);
        Ok(Cow::Owned(combined))
    }

    fn decrypt_internal<'a, T: Aead>(data: &'a [u8], cipher: &T) -> Result<Cow<'a, [u8]>, CipherError> {
        if data.len() < 12 {
            return Err(CipherError::InvalidNonce);
        }

        // The first 12 bytes are the nonce
        let nonce_bytes = &data[..12];
        let nonce = nonce_bytes.try_into()
            .map_err(|_| CipherError::InvalidNonce)?;

        let decrypted_data = cipher.decrypt(&nonce, &data[12..])
            .map_err(|_| CipherError::DecryptionFailed)?;

        Ok(Cow::Owned(decrypted_data))
    }

    pub fn encrypt<'a>(&mut self, data: &'a [u8]) -> Result<Cow<'a, [u8]>, CipherError> {
        match &self.mode {
            CipherState::None => Ok(Cow::Borrowed(data)),
            CipherState::AES { cipher } => Self::encrypt_internal(data, cipher),
            CipherState::Chacha20Poly1305 { cipher } => Self::encrypt_internal(data, cipher),
        }
    }

    pub fn decrypt<'a>(&mut self, data: &'a [u8]) -> Result<Cow<'a, [u8]>, CipherError> {
        Ok(match &self.mode {
            CipherState::None => Cow::Borrowed(data),
            CipherState::AES { cipher } => Self::decrypt_internal(data, cipher)?,
            CipherState::Chacha20Poly1305 { cipher } => Self::decrypt_internal(data, cipher)?,
        })
    }
}