pub mod transaction_builder;

use std::borrow::Cow;

use crate::core::json_rpc::{JsonRPCClient, JsonRPCError};
use crate::core::serializer::Serializer;
use crate::crypto::address::{Address, AddressType};
use crate::crypto::key::KeyPair;
use crate::core::transaction::{Transaction, TransactionType};
use crate::core::error::BlockchainError;
use crate::rpc::rpc::SubmitTransactionParams;

pub enum WalletError {
    InvalidKeyPair,
    ExpectedOneTx,
    TxOwnerIsReceiver
}

pub struct Wallet {
    keypair: KeyPair,
    balance: u64,
    nonce: u64,
    transactions: Vec<Transaction>,
    client: JsonRPCClient
}

impl Wallet {
    pub fn new(daemon_address: String) -> Self {
        Wallet {
            keypair: KeyPair::new(),
            balance: 0,
            nonce: 0,
            transactions: Vec::new(),
            client: JsonRPCClient::new(daemon_address)
        }
    }

    pub fn get_address(&self) -> Address {
        Address::new(true, AddressType::Normal, Cow::Borrowed(self.keypair.get_public_key()))
    }

    pub fn send_transaction(&self, transaction: &Transaction) -> Result<(), JsonRPCError> {
        self.client.notify_with("submit_transaction", &SubmitTransactionParams { data: transaction.to_hex() })
    }

    pub fn create_tx_registration(&self) -> Transaction {
        panic!("") //Transaction::new(self.keypair.get_public_key().clone(), TransactionVariant::Registration)
    }

    pub fn create_transaction(&self, data: TransactionType) -> Result<Transaction, BlockchainError> {
        panic!("")
        /*let mut tx = Transaction::new(self.keypair.get_public_key().clone(), TransactionVariant::Normal { nonce: self.nonce, fee: 0, data });
        let fee = calculate_tx_fee(tx.size() + SIGNATURE_LENGTH);
        tx.set_fee(fee)?;
        tx.sign(&self.keypair);
        Ok(tx)*/
    }

    pub fn get_transactions(&self) -> &Vec<Transaction> {
       &self.transactions
    }

    pub fn get_balance(&self) -> u64 {
        self.balance
    }
}