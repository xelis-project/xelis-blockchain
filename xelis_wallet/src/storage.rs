use rand::RngCore;
use sled::{Tree, Db};
use xelis_common::{
    crypto::{hash::Hash, key::KeyPair},
    serializer::{Reader, Serializer},
    transaction::Transaction
};
use chacha20poly1305::aead::OsRng;
use anyhow::{Context, Result};
use crate::{config::SALT_SIZE, cipher::Cipher, wallet::WalletError};

// keys used to retrieve from storage
const NONCE_KEY: &[u8] = b"NONCE";
const SALT_KEY: &[u8] = b"SALT";
// Password + salt is necessary to decrypt master key
const PASSWORD_SALT_KEY: &[u8] = b"PSALT";
// Master key to encrypt/decrypt while interacting with the storage 
const MASTER_KEY: &[u8] = b"MKEY";
const KEY_PAIR: &[u8] = b"KPAIR";

// Use this struct to get access to non-encrypted keys (such as salt for KDF and encrypted master key)
pub struct Storage {
    db: Db
}

// Implement an encrypted storage system 
pub struct EncryptedStorage {
    cipher: Cipher,
    transactions: Tree,
    balances: Tree,
    extra: Tree,
    inner: Storage
}

impl EncryptedStorage {
    pub fn new(inner: Storage, key: &[u8]) -> Result<Self> {
        // generate (or retrieve) salt for trees/keys
        let mut salt = [0; SALT_SIZE];
        match inner.db.get(SALT_KEY)? {
            Some(bytes) => {
                salt.copy_from_slice(&bytes);
            },
            None => {
                OsRng.fill_bytes(&mut salt);
            }
        };

        let cipher = Cipher::new(key, Some(salt))?;
        let storage = Self {
            transactions: inner.db.open_tree(&cipher.hash_key("transactions"))?,
            balances: inner.db.open_tree(&cipher.hash_key("balances"))?,
            extra: inner.db.open_tree(&cipher.hash_key("extra"))?,
            cipher,
            inner
        };
        Ok(storage)
    }

    // load from disk, decrypt the value and deserialize it
    fn load_from_disk<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V> {
        let data = tree.get(self.cipher.encrypt_value(key)?)?.context(format!("load from disk: tree = {:?}, key = {:?}", tree.name(), key))?;
        let bytes = self.cipher.decrypt_value(&data)?;
        let mut reader = Reader::new(&bytes);
        Ok(V::read(&mut reader)?)
    }

    // hash key, encrypt data and then save to disk 
    fn save_to_disk(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<()> {
        tree.insert(self.cipher.hash_key(key), self.cipher.encrypt_value(value)?)?;
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

    pub fn set_keypair(&self, keypair: KeyPair) -> Result<()> {
        self.save_to_disk(&self.extra, KEY_PAIR, &keypair.to_bytes())
    }

    pub fn get_keypair(&self) -> Result<KeyPair> {
        self.load_from_disk(&self.extra, KEY_PAIR)
    }

    pub fn get_public_storage(&self) -> &Storage {
        &self.inner
    }
}

impl Storage {
    pub fn new(name: String) -> Result<Self> {
        let db = sled::open(name)?;

        Ok(Self {
            db
        })
    }

    // save the encrypted form of the master key
    // it can only be decrypted using the password-based key
    pub fn set_encrypted_master_key(&self, encrypted_key: &[u8]) -> Result<()> {
        self.db.insert(MASTER_KEY, encrypted_key)?;
        Ok(())
    }

    pub fn get_encrypted_master_key(&self) -> Result<Vec<u8>> {
        match self.db.get(MASTER_KEY)? {
            Some(key) => {
                Ok(key.to_vec())
            }
            None => {
                Err(WalletError::NoMasterKeyFound.into())
            }
        }
    }

    pub fn set_password_salt(&self, salt: &[u8]) -> Result<()> {
        self.db.insert(PASSWORD_SALT_KEY, salt)?;
        Ok(())
    }

    pub fn get_password_salt(&self) -> Result<[u8; SALT_SIZE]> {
        let mut salt: [u8; SALT_SIZE] = [0; SALT_SIZE];

        match self.db.get(PASSWORD_SALT_KEY)? {
            Some(value) => {
                if value.len() != SALT_SIZE {
                    return Err(WalletError::InvalidSaltSize.into())
                }
                salt.copy_from_slice(&value);
            }
            None => {
                return Err(WalletError::NoMasterKeyFound.into())
            }
        };

        Ok(salt)
    }
}