use anyhow::{Error, Context};
use xelis_common::crypto::key::KeyPair;
use crate::account::Account;
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
    storage: EncryptedStorage,
    // account to receive / generate txs
    account: Option<Account>,
    // Cipher to encrypt / decrypt the master key
    cipher: Cipher
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

        // generate the master key which is used for storage
        let mut master_key: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut master_key);

        debug!("Creating storage for {}", name);
        let inner = Storage::new(name)?;
        debug!("Creating encrypted storage");
        let storage = EncryptedStorage::new(inner, &master_key)?;

        // save the salt used for password
        debug!("Save password salt in public storage");
        storage.get_public_storage().set_password_salt(&salt)?;

        // generate the Cipher
        let cipher = Cipher::new(&hashed_password, None)?;
        // encrypt the master key
        let encrypted_master_key = cipher.encrypt_value(&master_key)?;

        // now we save the master key in encrypted form
        debug!("Save encrypted master key in public storage");
        storage.get_public_storage().set_encrypted_master_key(&encrypted_master_key)?;

        let mut wallet = Self {
            account: None,
            storage,
            cipher
        };

        // generate random keypair
        let keypair = KeyPair::new();
        wallet.init_account(daemon_address, keypair);

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

        debug!("Creating encrypted storage");
        let storage = EncryptedStorage::new(storage, &master_key)?;
        let keypair =  storage.get_keypair()?;

        let mut wallet = Self {
            account: None,
            storage,
            cipher,
        };

        wallet.init_account(daemon_address, keypair);

        Ok(wallet)
    }

    fn init_account(&mut self, daemon_address: String, keypair: KeyPair) {
        debug!("init account");
        //self.account = Some(Account::new(daemon_address, keypair));
    }
}