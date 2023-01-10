use rand::RngCore;
use sled::Tree;
use crate::{crypto::hash::{Hash, hash, HASH_SIZE}, core::{error::{DiskContext, BlockchainError}, serializer::Serializer, reader::Reader, transaction::Transaction}};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce
};

const NONCE: &[u8] = b"NONCE";
const SALT: &[u8] = b"SALT";

use anyhow::Result;

use super::WalletError;

pub struct Encryption {
    cipher: XChaCha20Poly1305,
    salt: Vec<u8>
}

impl Encryption {
    pub fn new(key: &[u8], salt: Vec<u8>) -> Result<Self> {
        Ok(Self {
            cipher: XChaCha20Poly1305::new_from_slice(key)?,
            salt
        })
    }

    // encrypt value passed in param and add plaintext nonce before encrypted value
    // a Nonce is generated randomly at each call
    pub fn encrypt_value(&self, value: &[u8]) -> Result<Vec<u8>, WalletError> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let data = &self.cipher.encrypt(&nonce, value).map_err(|e| WalletError::CryptoError(e))?;
        let mut encrypted = Vec::with_capacity(nonce.len() + data.len());
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(data);
        Ok(encrypted)
    }

    // decrypt any value loaded from disk, with the format of above function
    pub fn decrypt_value(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < 25 {
            return Err(WalletError::InvalidEncryptedValue.into())
        }
        let nonce = XNonce::from_slice(&encrypted[0..24]);
        let decrypted = self.cipher.decrypt(nonce, &encrypted[nonce.len() + 1..]).map_err(|e| WalletError::CryptoError(e))?;
        Ok(decrypted)
    }

    // hash the key with salt
    pub fn hash_key<S: AsRef<[u8]>>(&self, key: S) -> [u8; HASH_SIZE] {
        let mut data = Vec::with_capacity(self.salt.len());
        data.extend_from_slice(&self.salt);
        data.extend_from_slice(key.as_ref());
        hash(&data).to_bytes()
    }
}
// Implement an encrypted storage system 
pub struct Storage {
    encryption: Encryption,
    transactions: Tree,
    balances: Tree,
    extra: Tree
}

impl Storage {
    pub fn new(name: String, key: &[u8]) -> Result<Self> {
        let db = sled::open(name)?;
        // generate (or retrieve) salt for trees/keys
        let salt = match db.get(SALT)? {
            Some(bytes) => bytes.to_vec(),
            None => {
                let mut salt = Vec::with_capacity(64);
                OsRng.fill_bytes(&mut salt);
                salt
            }
        };
        let encryption = Encryption::new(key, salt)?;
        let storage = Self {
            transactions: db.open_tree(&encryption.hash_key("transactions"))?,
            balances: db.open_tree(&encryption.hash_key("balances"))?,
            extra: db.open_tree(&encryption.hash_key("extra"))?,
            encryption
        };
        Ok(storage)
    }

    fn load_from_disk<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V> {
        match tree.get(self.encryption.encrypt_value(key)?)? {
            Some(bytes) => {
                let bytes = self.encryption.decrypt_value(&bytes)?;
                let mut reader = Reader::new(&bytes);
                Ok(V::read(&mut reader)?)
            },
            None => Err(BlockchainError::NotFoundOnDisk(DiskContext::LoadData).into())
        }
    }

    fn save_to_disk(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<()> {
        tree.insert(self.encryption.hash_key(key), self.encryption.encrypt_value(value)?)?;
        Ok(())
    }

    pub fn get_balance_for(&self, asset: &Hash) -> Result<u64> {
        self.load_from_disk(&self.balances, asset.as_bytes())
    }

    pub fn set_balance_for(&self, asset: &Hash, value: u64) -> Result<()> {
        self.save_to_disk(&self.balances, asset.as_bytes(), &value.to_be_bytes())
    }

    pub fn get_transaction(&self, hash: &Hash) -> Result<Transaction> {
        self.load_from_disk(&self.transactions, hash.as_bytes())
    }

    pub fn save_transaction(&self, hash: &Hash, transaction: &Transaction) -> Result<()> {
        self.save_to_disk(&self.transactions, hash.as_bytes(), &transaction.to_bytes())
    }

    pub fn get_nonce(&self) -> Result<u64> {
        self.load_from_disk(&self.extra, NONCE)
    }

    pub fn set_nonce(&self, nonce: u64) -> Result<()> {
        self.save_to_disk(&self.extra, NONCE, &nonce.to_be_bytes())
    }
}