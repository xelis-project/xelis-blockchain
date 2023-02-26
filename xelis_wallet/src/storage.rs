use std::collections::HashSet;

use sled::{Tree, Db};
use xelis_common::{
    crypto::{hash::Hash, key::KeyPair},
    serializer::{Reader, Serializer}, network::Network,
};
use anyhow::{Context, Result, anyhow};
use crate::{config::SALT_SIZE, cipher::Cipher, wallet::WalletError, entry::TransactionEntry};

// keys used to retrieve from storage
const NONCE_KEY: &[u8] = b"NONCE";
const SALT_KEY: &[u8] = b"SALT";
// Password + salt is necessary to decrypt master key
const PASSWORD_SALT_KEY: &[u8] = b"PSALT";
// Master key to encrypt/decrypt while interacting with the storage 
const MASTER_KEY: &[u8] = b"MKEY";
const KEY_PAIR: &[u8] = b"KPAIR";

// const used for online mode
// represent the daemon topoheight
const TOPOHEIGHT_KEY: &[u8] = b"TOPH";
// represent the daemon top block hash
const TOP_BLOCK_HASH_KEY: &[u8] = b"TOPBH";
const NETWORK: &[u8] = b"NET";

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
    assets: Tree,
    inner: Storage
}

impl EncryptedStorage {
    pub fn new(inner: Storage, key: &[u8], salt: [u8; SALT_SIZE], network: Network) -> Result<Self> {
        let cipher = Cipher::new(key, Some(salt))?;
        let storage = Self {
            transactions: inner.db.open_tree(&cipher.hash_key("transactions"))?,
            balances: inner.db.open_tree(&cipher.hash_key("balances"))?,
            extra: inner.db.open_tree(&cipher.hash_key("extra"))?,
            assets: inner.db.open_tree(&cipher.hash_key("assets"))?,
            cipher,
            inner
        };

        if storage.has_network()? {
            let storage_network = storage.get_network()?;
            if storage_network != network {
                return Err(anyhow!("Network mismatch for this wallet storage (stored: {})!", storage_network));
            }
        } else {
            storage.set_network(&network)?;
        }

        Ok(storage)
    }

    // load from disk, decrypt the value and deserialize it
    fn load_from_disk<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V> {
        let hashed_key = self.cipher.hash_key(key);
        let data = tree.get(hashed_key)?.context(format!("load from disk: tree = {:?}, key = {}", tree.name(), String::from_utf8_lossy(key)))?;
        let bytes = self.cipher.decrypt_value(&data).context("Error while decrypting value from disk")?;
        let mut reader = Reader::new(&bytes);
        Ok(V::read(&mut reader).context("Error while de-serializing value from disk")?)
    }

    // hash key, encrypt data and then save to disk 
    fn save_to_disk(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<()> {
        let hashed_key = self.cipher.hash_key(key);
        tree.insert(hashed_key, self.cipher.encrypt_value(value)?)?;
        Ok(())
    }

    // hash key, encrypt data and then save to disk 
    fn delete_from_disk(&self, tree: &Tree, key: &[u8]) -> Result<()> {
        let hashed_key = self.cipher.hash_key(key);
        tree.remove(hashed_key)?;
        Ok(())
    }

    fn contains_data(&self, tree: &Tree, key: &[u8]) -> Result<bool> {
        let hashed_key = self.cipher.hash_key(key);
        Ok(tree.contains_key(hashed_key)?)
    }
    // this function is specific because we save the key in encrypted form (and not hashed as others)
    // returns all saved assets
    pub fn get_assets(&self) -> Result<HashSet<Hash>> {
        let mut assets = HashSet::new();
        for res in self.assets.iter() {
            let (key, _) = res?;
            let raw_key = &self.cipher.decrypt_value(&key)?;
            let mut reader = Reader::new(raw_key);
            let asset = Hash::read(&mut reader)?;
            assets.insert(asset);
        }

        Ok(assets)
    }

    // we can't use a simple Tree#contains_key because of the encrypted form
    // and we can't encrypt it first because of the random nonce generated each time
    // so we currently read the whole tree
    // TODO build a cache instead of read the whole tree each time
    // will be necessary when we will have a lot of assets registered on chain
    pub fn contains_asset(&self, asset: &Hash) -> Result<bool> {
        Ok(self.get_assets()?.contains(asset))
    }

    // save asset in encrypted form
    pub fn add_asset(&mut self, asset: &Hash) -> Result<()> {
        if self.contains_asset(asset)? {
            return Err(WalletError::AssetAlreadyRegistered.into());
        }

        let encrypted_asset = self.cipher.encrypt_value(asset.as_bytes())?;
        self.assets.insert(encrypted_asset, &[])?;
        Ok(())
    }

    pub fn get_balance_for(&self, asset: &Hash) -> Result<u64> {
        self.load_from_disk(&self.balances, asset.as_bytes())
    }

    pub fn set_balance_for(&mut self, asset: &Hash, value: u64) -> Result<()> {
        self.save_to_disk(&self.balances, asset.as_bytes(), &value.to_be_bytes())
    }

    pub fn get_transaction(&self, hash: &Hash) -> Result<TransactionEntry> {
        self.load_from_disk(&self.transactions, hash.as_bytes())
    }

    // read whole disk and returns all transactions
    pub fn get_transactions(&self) -> Result<Vec<TransactionEntry>> {
        let mut transactions = Vec::new();
        for res in self.transactions.iter() {
            let (_, value) = res?;
            let raw_value = &self.cipher.decrypt_value(&value)?;
            let mut reader = Reader::new(raw_value);
            let transaction = TransactionEntry::read(&mut reader)?;
            transactions.push(transaction);
        }

        Ok(transactions)
    }

    pub fn delete_transaction(&mut self, hash: &Hash) -> Result<()> {
        self.transactions.remove(hash.as_bytes())?;
        Ok(())
    }

    pub fn delete_transactions(&mut self) -> Result<()> {
        self.transactions.clear()?;
        Ok(())
    }

    pub fn delete_balances(&mut self) -> Result<()> {
        self.balances.clear()?;
        Ok(())
    }

    pub fn save_transaction(&mut self, hash: &Hash, transaction: &TransactionEntry) -> Result<()> {
        self.save_to_disk(&self.transactions, hash.as_bytes(), &transaction.to_bytes())
    }

    pub fn get_nonce(&self) -> Result<u64> {
        self.load_from_disk(&self.extra, NONCE_KEY)
    }

    pub fn set_nonce(&mut self, nonce: u64) -> Result<()> {
        self.save_to_disk(&self.extra, NONCE_KEY, &nonce.to_be_bytes())
    }

    pub fn set_keypair(&mut self, keypair: &KeyPair) -> Result<()> {
        self.save_to_disk(&self.extra, KEY_PAIR, &keypair.to_bytes())
    }

    pub fn get_keypair(&self) -> Result<KeyPair> {
        self.load_from_disk(&self.extra, KEY_PAIR)
    }

    pub fn set_daemon_topoheight(&mut self, topoheight: u64) -> Result<()> {
        self.save_to_disk(&self.extra, TOPOHEIGHT_KEY, &topoheight.to_be_bytes())
    }

    pub fn get_daemon_topoheight(&self) -> Result<u64> {
        self.load_from_disk(&self.extra, TOPOHEIGHT_KEY)
    }

    pub fn delete_top_block_hash(&mut self) -> Result<()> {
        self.delete_from_disk(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    pub fn set_top_block_hash(&mut self, hash: &Hash) -> Result<()> {
        self.save_to_disk(&self.extra, TOP_BLOCK_HASH_KEY, hash.as_bytes())
    }

    pub fn has_top_block_hash(&mut self) -> Result<bool> {
        self.contains_data(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    pub fn get_top_block_hash(&self) -> Result<Hash> {
        self.load_from_disk(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    pub fn get_public_storage(&self) -> &Storage {
        &self.inner
    }

    pub fn get_mutable_public_storage(&mut self) -> &mut Storage {
        &mut self.inner
    }

    fn get_network(&self) -> Result<Network> {
        self.load_from_disk(&self.extra, NETWORK)
    }

    fn set_network(&self, network: &Network) -> Result<()> {
        self.save_to_disk(&self.extra, NETWORK, &network.to_bytes())
    }
    fn has_network(&self) -> Result<bool> {
        self.contains_data(&self.extra, NETWORK)
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
    pub fn set_encrypted_master_key(&mut self, encrypted_key: &[u8]) -> Result<()> {
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

    pub fn set_password_salt(&mut self, salt: &[u8]) -> Result<()> {
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

    pub fn get_encrypted_storage_salt(&self) -> Result<Vec<u8>> {
        let values = self.db.get(SALT_KEY)?.context("encrypted salt for storage was not found")?;
        let mut encrypted_salt = Vec::with_capacity(values.len());
        encrypted_salt.extend_from_slice(&values);

        Ok(encrypted_salt)
    }

    pub fn set_encrypted_storage_salt(&mut self, salt: &[u8]) -> Result<()> {
        self.db.insert(SALT_KEY, salt)?;
        Ok(())
    }
}