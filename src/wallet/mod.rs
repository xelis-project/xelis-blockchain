pub mod transaction_builder;
pub mod storage;

use crate::config::{DEFAULT_DAEMON_ADDRESS, DEFAULT_DIR_PATH};
use crate::core::json_rpc::JsonRPCClient;
use crate::crypto::key::KeyPair;

use self::storage::Storage;

pub enum WalletError {
    InvalidKeyPair,
    ExpectedOneTx,
    TxOwnerIsReceiver
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
        Wallet {
            keypair: KeyPair::new(),
            storage: Storage::new(config.name).unwrap(),
            client: JsonRPCClient::new(config.daemon_address)
        }
    }
}