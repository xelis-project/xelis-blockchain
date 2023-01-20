use rand::RngCore;
use sled::Tree;
use xelis_common::{
    crypto::hash::{Hash, hash, HASH_SIZE},
    serializer::{Reader, Serializer},
    transaction::Transaction
};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce
};
use anyhow::{Context, Result};
use crate::{wallet::WalletError, config::SALT_SIZE};

// keys used to retrieve from storage
const NONCE_KEY: &[u8] = b"NONCE";
const SALT_KEY: &[u8] = b"SALT";

pub struct Encryption {
    cipher: XChaCha20Poly1305,
    // this salt is used for keys and values
    salt: [u8; SALT_SIZE]
}

impl Encryption {
    pub fn new(key: &[u8], salt: [u8; SALT_SIZE]) -> Result<Self> {
        Ok(Self {
            cipher: XChaCha20Poly1305::new_from_slice(key)?,
            salt
        })
    }

    // encrypt value passed in param and add plaintext nonce before encrypted value
    // a Nonce is generated randomly at each call
    pub fn encrypt_value(&self, value: &[u8]) -> Result<Vec<u8>, WalletError> {
        // generate unique random nonce
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        // add salt to the plaintext value
        let mut plaintext: Vec<u8> = Vec::with_capacity(SALT_SIZE + value.len());
        plaintext.copy_from_slice(&self.salt);
        plaintext.extend_from_slice(value);

        // encrypt data using plaintext and nonce
        let data = &self.cipher.encrypt(&nonce, value).map_err(|e| WalletError::CryptoError(e))?;

        // append unique nonce to the encrypted data
        let mut encrypted = Vec::with_capacity(nonce.len() + data.len());
        encrypted.extend_from_slice(&nonce);
        encrypted.extend_from_slice(data);

        Ok(encrypted)
    }

    // decrypt any value loaded from disk, with the format of above function
    pub fn decrypt_value(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        // nonce is 24 bytes and is mandatory in encrypted slice
        if encrypted.len() < 25 {
            return Err(WalletError::InvalidEncryptedValue.into())
        }

        // read the nonce for this data 
        let nonce = XNonce::from_slice(&encrypted[0..24]);
        // decrypt the value using the nonce previously decoded
        let mut decrypted = self.cipher.decrypt(nonce, &encrypted[nonce.len() + 1..]).map_err(|e| WalletError::CryptoError(e))?;
        // delete the salt from the decrypted slice
        decrypted.drain(0..self.salt.len());

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
        let mut salt = [0; SALT_SIZE];
        match db.get(SALT_KEY)? {
            Some(bytes) => {
                salt.copy_from_slice(&bytes);
            },
            None => {
                OsRng.fill_bytes(&mut salt);
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
        let data = tree.get(self.encryption.encrypt_value(key)?)?.context(format!("load from disk: tree = {:?}, key = {:?}", tree.name(), key))?;
        let bytes = self.encryption.decrypt_value(&data)?;
        let mut reader = Reader::new(&bytes);
        Ok(V::read(&mut reader)?)
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
        self.load_from_disk(&self.extra, NONCE_KEY)
    }

    pub fn set_nonce(&self, nonce: u64) -> Result<()> {
        self.save_to_disk(&self.extra, NONCE_KEY, &nonce.to_be_bytes())
    }
}