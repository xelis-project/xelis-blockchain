use anyhow::{Error, Context};
use xelis_common::crypto::address::Address;
use xelis_common::crypto::key::KeyPair;
use crate::cipher::Cipher;
use crate::config::{PASSWORD_ALGORITHM, PASSWORD_HASH_SIZE, SALT_SIZE};
use crate::storage::{EncryptedStorage, Storage};
use chacha20poly1305::{aead::OsRng, Error as CryptoError};
use rand::RngCore;
use thiserror::Error;
use log::{error, debug};

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid key pair")]
    InvalidKeyPair,
    #[error("Expected a TX")]
    ExpectedOneTx,
    #[error("Transaction owner is the receiver")]
    TxOwnerIsReceiver,
    #[error("Error from crypto: {}", _0)]
    CryptoError(CryptoError),
    #[error("Unexpected error on database: {}", _0)]
    DatabaseError(#[from] sled::Error),
    #[error("Invalid encrypted value: minimum 25 bytes")]
    InvalidEncryptedValue,
    #[error("No salt found in storage")]
    NoSalt,
    #[error("Error while hashing: {}", _0)]
    AlgorithmHashingError(String),
    #[error("Error while fetching encrypted master key from DB")]
    NoMasterKeyFound,
    #[error("Invalid salt size stored in storage, expected 32 bytes")]
    InvalidSaltSize,
    #[error("Error while fetching password salt from DB")]
    NoSaltFound
}

pub struct Wallet {
    // Encrypted Wallet Storage
    storage: EncryptedStorage,
    // Private & Public key linked for this wallet
    keypair: KeyPair
}

pub fn hash_password(password: String, salt: &[u8]) -> Result<[u8; PASSWORD_HASH_SIZE], WalletError> {
    let mut output = [0; PASSWORD_HASH_SIZE];
    PASSWORD_ALGORITHM.hash_password_into(password.as_bytes(), salt, &mut output).map_err(|e| WalletError::AlgorithmHashingError(e.to_string()))?;
    Ok(output)
}

impl Wallet {
    pub fn new(name: String, password: String, daemon_address: String) -> Result<Self, Error> {
        // generate random salt for hashed password
        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);

        // generate hashed password which will be used as key to encrypt master_key
        debug!("hashing provided password");
        let hashed_password = hash_password(password, &salt)?;

        debug!("Creating storage for {}", name);
        let inner = Storage::new(name)?;

        // generate the Cipher
        let cipher = Cipher::new(&hashed_password, None)?;

        // save the salt used for password
        debug!("Save password salt in public storage");
        inner.set_password_salt(&salt)?;

        // generate the master key which is used for storage and then save it in encrypted form
        let mut master_key: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut master_key);
        let encrypted_master_key = cipher.encrypt_value(&master_key)?;
        debug!("Save encrypted master key in public storage");
        inner.set_encrypted_master_key(&encrypted_master_key)?;
        
        // generate the storage salt and save it in encrypted form
        let mut storage_salt = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut storage_salt);
        let encrypted_storage_salt = cipher.encrypt_value(&storage_salt)?;
        inner.set_encrypted_storage_salt(&encrypted_storage_salt)?;

        debug!("Creating encrypted storage");
        let storage = EncryptedStorage::new(inner, &master_key, storage_salt)?;

        // generate random keypair and save it to encrypted storage
        let keypair = KeyPair::new();
        storage.set_keypair(&keypair)?;

        let wallet = Self {
            storage,
            keypair
        };

        Ok(wallet)
    }

    pub fn open(name: String, password: String, daemon_address: String) -> Result<Self, Error> {
        debug!("Creating storage for {}", name);
        let storage = Storage::new(name)?;
        
        // get password salt for KDF
        debug!("Retrieving password salt from public storage");
        let salt = storage.get_password_salt()?;

        // retrieve encrypted master key from storage
        debug!("Retrieving encrypted master key from public storage");
        let encrypted_master_key = storage.get_encrypted_master_key()?;

        let hashed_password = hash_password(password, &salt)?;

        // decrypt the encrypted master key using the hashed password (used as key)
        let cipher = Cipher::new(&hashed_password, None)?;
        let master_key = cipher.decrypt_value(&encrypted_master_key).context("Invalid password provided for this wallet")?;

        // Retrieve the encrypted storage salt
        let encrypted_storage_salt = storage.get_encrypted_storage_salt()?;
        let storage_salt = cipher.decrypt_value(&encrypted_storage_salt).context("Invalid encrypted storage salt for this wallet")?;
        if storage_salt.len() != SALT_SIZE {
            error!("Invalid size received after decrypting storage salt: {} bytes", storage_salt.len());
            return Err(WalletError::InvalidSaltSize.into());
        }

        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        salt.copy_from_slice(&storage_salt);

        debug!("Creating encrypted storage");
        let storage = EncryptedStorage::new(storage, &master_key, salt)?;
        debug!("Retrieving keypair from encrypted storage");
        let keypair =  storage.get_keypair()?;

        let wallet = Self {
            storage,
            keypair
        };

        Ok(wallet)
    }

    pub fn set_password(&self, old_password: String, password: String) -> Result<(), Error> {
        let storage = self.storage.get_public_storage();
        let (master_key, storage_salt) = {
            // retrieve old salt to build key from current password
            let salt = storage.get_password_salt()?;
            let hashed_password = hash_password(old_password, &salt)?;

            let encrypted_master_key = storage.get_encrypted_master_key()?;
            let encrypted_storage_salt = storage.get_encrypted_storage_salt()?;

            // decrypt the encrypted master key using the provided password
            let cipher = Cipher::new(&hashed_password, None)?;
            let master_key = cipher.decrypt_value(&encrypted_master_key).context("Invalid password provided")?;
            let storage_salt = cipher.decrypt_value(&encrypted_storage_salt)?;
            (master_key, storage_salt)
        };

        // generate a new salt for password
        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);

        // generate the password-based derivated key to encrypt the master key
        let hashed_password = hash_password(password, &salt)?;
        let cipher = Cipher::new(&hashed_password, None)?;

        // encrypt the master key using the new password
        let encrypted_key = cipher.encrypt_value(&master_key)?;

        // encrypt the salt with the new password
        let encrypted_storage_salt = cipher.encrypt_value(&storage_salt)?;

        // save on disk
        storage.set_password_salt(&salt)?;
        storage.set_encrypted_master_key(&encrypted_key)?;
        storage.set_encrypted_storage_salt(&encrypted_storage_salt)?;

        Ok(())
    }

    pub fn get_address(&self) -> Address<'_> {
        self.keypair.get_public_key().to_address()
    }
}