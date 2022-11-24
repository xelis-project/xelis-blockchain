use sled::{Tree, Error};

use crate::{crypto::hash::Hash, core::{error::{BlockchainError, DiskContext}, serializer::Serializer, reader::Reader, transaction::Transaction}};

const NONCE: &[u8] = b"NONCE";

// Implement an encrypted storage system 
pub struct Storage {
    transactions: Tree,
    balances: Tree,
    extra: Tree
}

impl Storage {
    pub fn new(name: String) -> Result<Self, Error> {
        let db = sled::open(name)?;
        Ok(Self { // TODO encrypt tree names
            transactions: db.open_tree("transactions")?,
            balances: db.open_tree("balances")?,
            extra: db.open_tree("extra")?
        })
    }

    fn encrypt(&self, value: &[u8]) -> &[u8] {
        &[0u8; 0]
    }

    fn decrypt(&self, encrypted: &[u8]) -> &[u8] {
        &[0u8; 0]
    }

    fn load_from_disk<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V, BlockchainError> {
        match tree.get(self.encrypt(key))? {
            Some(bytes) => {
                let bytes = self.decrypt(&bytes);
                let mut reader = Reader::new(&bytes);
                Ok(V::read(&mut reader)?)
            },
            None => Err(BlockchainError::NotFoundOnDisk(DiskContext::LoadData))
        }
    }

    fn save_to_disk(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<(), BlockchainError> {
        tree.insert(self.encrypt(key), self.encrypt(value))?;
        Ok(())
    }

    pub fn get_balance_for(&self, asset: &Hash) -> Result<u64, BlockchainError> {
        self.load_from_disk(&self.balances, asset.as_bytes())
    }

    pub fn set_balance_for(&self, asset: &Hash, value: u64) -> Result<(), BlockchainError> {
        self.save_to_disk(&self.balances, asset.as_bytes(), &value.to_be_bytes())
    }

    pub fn get_transaction(&self, hash: &Hash) -> Result<Transaction, BlockchainError> {
        self.load_from_disk(&self.transactions, hash.as_bytes())
    }

    pub fn save_transaction(&self, hash: &Hash, transaction: &Transaction) -> Result<(), BlockchainError> {
        self.save_to_disk(&self.transactions, hash.as_bytes(), &transaction.to_bytes())
    }

    pub fn get_nonce(&self) -> Result<u64, BlockchainError> {
        self.load_from_disk(&self.extra, NONCE)
    }

    pub fn set_nonce(&self, nonce: u64) -> Result<(), BlockchainError> {
        self.save_to_disk(&self.extra, NONCE, &nonce.to_be_bytes())
    }
}