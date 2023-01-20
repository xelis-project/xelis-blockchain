use anyhow::Error;
use xelis_common::{
    json_rpc::JsonRPCClient,
    crypto::key::KeyPair
};
use crate::config::{PASSWORD_ALGORITHM, PASSWORD_HASH_SIZE, SALT_SIZE};
use crate::storage::Storage;
use chacha20poly1305::{aead::OsRng, Error as CryptoError};
use rand::RngCore;
use thiserror::Error;
use log::error;

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
    AlgorithmHashingError(String)
}

pub struct Wallet {
    keypair: KeyPair,
    storage: Storage,
    client: JsonRPCClient,
    // salt used when hashing user password
    salt: [u8; SALT_SIZE],
    // hashed password to save wallet
    hashed_password: [u8; PASSWORD_HASH_SIZE]
}


pub fn hash_password(password: String, salt: &[u8]) -> Result<[u8; PASSWORD_HASH_SIZE], argon2::Error> {
    let mut output = [0; PASSWORD_HASH_SIZE];
    PASSWORD_ALGORITHM.hash_password_into(password.as_bytes(), salt, &mut output)?;
    Ok(output)
}

impl Wallet {
    pub fn new(name: String, password: String, daemon_address: String) -> Result<Self, Error> {
        // generate random salt for hashed password
        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        // generate hashed password which will be used as key to encrypt master_key
        let hashed_password = hash_password(password, &salt).map_err(|e| WalletError::AlgorithmHashingError(e.to_string()))?;

        // generate the master key which is used for storage
        let mut master_key: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut master_key);

        Ok(Wallet {
            keypair: KeyPair::new(),
            storage: Storage::new(name, &master_key)?,
            client: JsonRPCClient::new(daemon_address),
            hashed_password,
            salt
        })
    }

    pub fn open(name: String, password: String, daemon_address: String) -> Result<Self, Error> {
        todo!("Open an existing wallet")
    }
}