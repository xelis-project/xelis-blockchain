use crate::crypto::key::KeyPair;
use crate::core::transaction::{Transaction, TransactionData};
use crate::core::error::BlockchainError;

pub struct Wallet {
    keypair: KeyPair,
    balance: u64,
    nonce: u64,
    transactions: Vec<Transaction>
}

impl Wallet {
    pub fn new() -> Self {
        Wallet {
            keypair: KeyPair::new(),
            balance: 0,
            nonce: 0,
            transactions: vec![],
        }
    }

    pub fn get_address(&self) -> String {
        self.keypair.get_public_key().to_address().unwrap()
    }

    pub fn create_transaction(&self, data: TransactionData) -> Result<Transaction, BlockchainError> {
        //let mut transaction = Transaction::new(self.keypair.get_public_key().clone());
        //transaction.sign(&self.keypair)?;
        panic!("not implemented")
    }

    pub fn get_transactions(&self) -> &Vec<Transaction> {
       &self.transactions
    }

    pub fn get_balance(&self) -> u64 {
        self.balance
    }
}