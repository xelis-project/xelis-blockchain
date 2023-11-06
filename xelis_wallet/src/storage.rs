use std::collections::HashSet;

use sled::{Tree, Db};
use xelis_common::{
    crypto::{hash::Hash, key::{KeyPair, PublicKey}},
    serializer::{Reader, Serializer},
    network::Network,
    api::wallet::QuerySearcher,
};
use anyhow::{Context, Result, anyhow};
use crate::{config::SALT_SIZE, cipher::Cipher, wallet::WalletError, entry::{TransactionEntry, EntryData}};

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
        let mut storage = Self {
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

    // Key must be hashed or encrypted before calling this function
    fn internal_load<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V> {
        let data = tree.get(key)?.context(format!("load from disk: tree = {:?}, key = {}", tree.name(), String::from_utf8_lossy(key)))?;
        let bytes = self.cipher.decrypt_value(&data).context("Error while decrypting value from disk")?;
        let mut reader = Reader::new(&bytes);
        Ok(V::read(&mut reader).context("Error while de-serializing value from disk")?)
    }

    // load from disk using a hashed key, decrypt the value and deserialize it
    fn load_from_disk<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V> {
        let hashed_key = self.cipher.hash_key(key);
        self.internal_load(tree, &hashed_key)
    }

    // load from disk using an encrypted key, decrypt the value and deserialize it
    fn load_from_disk_with_encrypted_key<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V> {
        let encrypted_key = self.cipher.encrypt_value(key)?;
        self.internal_load(tree, &encrypted_key)
    }

    // hash key, encrypt data and then save to disk 
    fn save_to_disk(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<()> {
        let hashed_key = self.cipher.hash_key(key);
        tree.insert(hashed_key, self.cipher.encrypt_value(value)?)?;
        Ok(())
    }

    // Encrypt key, encrypt data and then save to disk
    // We encrypt instead of hashing to be able to retrieve the key
    fn save_to_disk_with_encrypted_key(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<()> {
        let encrypted_key = self.cipher.encrypt_value(key)?;
        tree.insert(encrypted_key, self.cipher.encrypt_value(value)?)?;
        Ok(())
    }

    // hash key, encrypt data and then save to disk 
    fn delete_from_disk(&self, tree: &Tree, key: &[u8]) -> Result<()> {
        let hashed_key = self.cipher.hash_key(key);
        tree.remove(hashed_key)?;
        Ok(())
    }

    // Search if the data is present in the tree using hashed key
    fn contains_data(&self, tree: &Tree, key: &[u8]) -> Result<bool> {
        let hashed_key = self.cipher.hash_key(key);
        Ok(tree.contains_key(hashed_key)?)
    }

    // Encrypt instead of hash the key to recover it later
    fn contains_encrypted_data(&self, tree: &Tree, key: &[u8]) -> Result<bool> {
        let encrypted_key = self.cipher.encrypt_value(key)?;
        Ok(tree.contains_key(encrypted_key)?)
    }

    // Open the named tree
    fn get_custom_tree(&self, name: &String) -> Result<Tree> {
        let hash = self.cipher.hash_key(format!("custom_{}", name));
        let tree = self.inner.db.open_tree(&hash)?;
        Ok(tree)
    }

    // Store a custom serializable data 
    pub fn set_custom_data<K: Serializer, V: Serializer>(&self, tree: &String, key: &K, value: &V) -> Result<()> {
        let tree = self.get_custom_tree(tree)?;
        self.save_to_disk_with_encrypted_key(&tree, &key.to_bytes(), &value.to_bytes())?;
        Ok(())
    }

    // Retrieve a custom data in the selected format
    pub fn get_custom_data<K: Serializer, V: Serializer>(&self, tree: &String, key: &K) -> Result<V> {
        let tree = self.get_custom_tree(tree)?;
        self.load_from_disk_with_encrypted_key(&tree, &key.to_bytes())
    }

    // Get all keys from the custom
    pub fn get_custom_tree_keys<K: Serializer>(&self, tree: &String) -> Result<Vec<K>> {
        let tree = self.get_custom_tree(tree)?;
        let mut keys = Vec::new();
        for e in tree.iter() {
            let (key, _) = e?;
            let k = K::from_bytes(&key)?;
            keys.push(k);
        }

        Ok(keys)
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

    // Retrieve all assets with their decimals
    pub fn get_assets_with_decimals(&self) -> Result<Vec<(Hash, u8)>> {
        let mut assets = Vec::new();
        for res in self.assets.iter() {
            let (key, value) = res?;
            let asset = Hash::from_bytes(&self.cipher.decrypt_value(&key)?)?;
            let decimals = u8::from_bytes(&self.cipher.decrypt_value(&value)?)?;

            assets.push((asset, decimals));
        }

        Ok(assets)
    }

    // Check if the asset is already registered
    pub fn contains_asset(&self, asset: &Hash) -> Result<bool> {
        self.contains_encrypted_data(&self.assets, asset.as_bytes())
    }

    // save asset with its corresponding decimals
    pub fn add_asset(&mut self, asset: &Hash, decimals: u8) -> Result<()> {
        if self.contains_asset(asset)? {
            return Err(WalletError::AssetAlreadyRegistered.into());
        }

        self.save_to_disk_with_encrypted_key(&self.assets, asset.as_bytes(), &decimals.to_be_bytes())
    }

    // Retrieve the stored decimals for this asset for better display
    pub fn get_asset_decimals(&self, asset: &Hash) -> Result<u8> {
        self.load_from_disk_with_encrypted_key(&self.assets, asset.as_bytes())
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
        self.get_filtered_transactions(None, None, None, true, true, true, true, None)
    }

    // Filter when the data is deserialized to not load all transactions in memory
    pub fn get_filtered_transactions(&self, address: Option<&PublicKey>, min_topoheight: Option<u64>, max_topoheight: Option<u64>, accept_incoming: bool, accept_outgoing: bool, accept_coinbase: bool, accept_burn: bool, key_value: Option<&QuerySearcher>) -> Result<Vec<TransactionEntry>> {
        let mut transactions = Vec::new();
        for res in self.transactions.iter() {
            let (_, value) = res?;
            let raw_value = &self.cipher.decrypt_value(&value)?;
            let mut e = TransactionEntry::from_bytes(raw_value)?;
            if let Some(topoheight) = min_topoheight {
                if e.get_topoheight() < topoheight {
                    continue;
                }
            }
    
            if let Some(topoheight) = &max_topoheight {
                if e.get_topoheight() > *topoheight {
                    continue;
                }
            }
    
            let (save, mut transfers) = match e.get_mut_entry() {
                EntryData::Coinbase(_) if accept_coinbase => (true, None),
                EntryData::Burn { .. } if accept_burn => (true, None),
                EntryData::Incoming(sender, transfers) if accept_incoming => match address {
                    Some(key) => (*key == *sender, Some(transfers)),
                    None => (true, None)
                },
                EntryData::Outgoing(txs) if accept_outgoing => match address {
                    Some(filter_key) => (txs.iter().find(|tx| {
                        *tx.get_key() == *filter_key
                    }).is_some(), Some(txs)),
                    None => (true, None),
                },
                _ => (false, None)
            };

            if save {
                // Check if it has requested extra data
                if let Some(key_value) = key_value {
                    if let Some(transfers) = transfers.as_mut() {
                        transfers.retain(|transfer| {
                            if let Some(element) = transfer.get_extra_data() {
                                match key_value {
                                    QuerySearcher::KeyValue { key, value: Some(v) } => {
                                        element.get_value_by_key(key, Some(v.kind())) == Some(v)
                                    },
                                    QuerySearcher::KeyValue { key, value: None } => {
                                        element.has_key(key)
                                    },
                                    QuerySearcher::KeyType { key, kind } => {
                                        element.get_value_by_key(key, Some(*kind)) != None
                                    }
                                }
                            } else {
                                false
                            }
                        });
                    } else {
                        // Coinbase, burn, etc will be discarded always with such filter
                        continue;
                    }
                }

                // Keep only transactions entries that have one transfer at least
                match transfers {
                    // Transfers which are not empty
                    Some(transfers) if !transfers.is_empty() => {
                        transactions.push(e);
                    },
                    // Something else than outgoing/incoming txs
                    None => {
                        transactions.push(e);
                    },
                    // All the left is discarded
                    _ => {}
                }
            }
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

    // Save the transaction with its TX hash as key
    // We hash the hash of the TX to use it as a key to not let anyone being able to see txs saved on disk
    // with no access to the decrypted master key
    pub fn save_transaction(&mut self, hash: &Hash, transaction: &TransactionEntry) -> Result<()> {
        self.save_to_disk(&self.transactions, hash.as_bytes(), &transaction.to_bytes())
    }

    pub fn has_transaction(&self, hash: &Hash) -> Result<bool> {
        self.contains_data(&self.transactions, hash.as_bytes())
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

    pub fn has_top_block_hash(&self) -> Result<bool> {
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

    fn set_network(&mut self, network: &Network) -> Result<()> {
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