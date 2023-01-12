use xelis_common::{
    json_rpc::JsonRPCClient,
    crypto::key::KeyPair,
    config::DEFAULT_DAEMON_ADDRESS,
    config::DEFAULT_DIR_PATH
};
use crate::storage::Storage;
use chacha20poly1305::{aead::OsRng, Error as CryptoError};
use rand::RngCore;
use thiserror::Error;

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
    NoSalt
}

#[derive(Debug, clap::StructOpt)]
pub struct Config {
    /// Daemon address to use
    #[clap(short, long, default_value_t = String::from(DEFAULT_DAEMON_ADDRESS))]
    daemon_address: String,
    /// Set name path for wallet storage
    #[clap(short = 'd', long, default_value_t = String::from(DEFAULT_DIR_PATH))]
    name: String
}

pub struct Wallet {
    keypair: KeyPair,
    storage: Storage,
    client: JsonRPCClient
}

impl Wallet {
    pub fn new(config: Config) -> Self {
        let mut key: [u8; 32] = [0; 32]; 
        OsRng.fill_bytes(&mut key);
        Wallet {
            keypair: KeyPair::new(),
            storage: Storage::new(config.name, &key).unwrap(),
            client: JsonRPCClient::new(config.daemon_address)
        }
    }
}