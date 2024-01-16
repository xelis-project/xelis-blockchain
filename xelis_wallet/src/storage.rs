use std::collections::HashSet;
use indexmap::IndexMap;
use sled::{Tree, Db};
use xelis_common::{
    crypto::{hash::Hash, key::{KeyPair, PublicKey}},
    serializer::{Reader, Serializer},
    network::Network,
    api::{DataValue, DataElement, query::{QueryResult, Query}},
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
    // cipher used to encrypt/decrypt/hash data
    cipher: Cipher,
    // All transactions where this wallet is part of
    transactions: Tree,
    // balances for each asset
    balances: Tree,
    // extra data (network, topoheight, etc)
    extra: Tree,
    // all assets tracked by the wallet
    assets: Tree,
    // This tree is used to store all topoheight where a change in the wallet occured
    changes_topoheight: Tree,
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
            changes_topoheight: inner.db.open_tree(&cipher.hash_key("changes_topoheight"))?,
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

    // Because we can't predict the nonce used for encryption, we make it determistic
    fn create_encrypted_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        // the hashed key is salted so its unique and can't be recover/bruteforced
        let hashed_key = self.cipher.hash_key(key);

        // Use only the first 24 bytes as nonce
        let mut nonce = [0u8; Cipher::NONCE_SIZE];
        nonce.copy_from_slice(&hashed_key[0..Cipher::NONCE_SIZE]);

        let key = self.cipher.encrypt_value_with_nonce(key, &nonce)?;
        Ok(key)
    }

    // load from disk using an encrypted key, decrypt the value and deserialize it
    fn load_from_disk_with_encrypted_key<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V> {
        let encrypted_key = self.create_encrypted_key(key)?;
        self.internal_load(tree, &encrypted_key)
    }

    // Encrypt key, encrypt data and then save to disk
    // We encrypt instead of hashing to be able to retrieve the key
    fn save_to_disk_with_encrypted_key(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<()> {
        let encrypted_key = self.create_encrypted_key(key)?;
        let encrypted_value = self.cipher.encrypt_value(value)?;
        tree.insert(encrypted_key, encrypted_value)?;
        Ok(())
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

    // hash key, encrypt data and then save to disk 
    fn delete_from_disk_with_encrypted_key(&self, tree: &Tree, key: &[u8]) -> Result<()> {
        let encrypted_key = self.create_encrypted_key(key)?;
        tree.remove(encrypted_key)?;
        Ok(())
    }

    // Search if the data is present in the tree using hashed key
    fn contains_data(&self, tree: &Tree, key: &[u8]) -> Result<bool> {
        let hashed_key = self.cipher.hash_key(key);
        Ok(tree.contains_key(hashed_key)?)
    }

    // Encrypt instead of hash the key to recover it later
    fn contains_encrypted_data(&self, tree: &Tree, key: &[u8]) -> Result<bool> {
        let encrypted_key = self.create_encrypted_key(key)?;
        Ok(tree.contains_key(encrypted_key)?)
    }

    // Open the named tree
    fn get_custom_tree(&self, name: impl Into<String>) -> Result<Tree> {
        let hash = self.cipher.hash_key(format!("custom_{}", name.into()));
        let tree = self.inner.db.open_tree(&hash)?;
        Ok(tree)
    }

    // Store a custom serializable data 
    pub fn set_custom_data(&mut self, tree: impl Into<String>, key: &DataValue, value: &DataElement) -> Result<()> {
        let tree = self.get_custom_tree(tree)?;
        self.save_to_disk_with_encrypted_key(&tree, &key.to_bytes(), &value.to_bytes())?;
        Ok(())
    }

    // Delete a custom data using its key 
    pub fn delete_custom_data(&mut self, tree: impl Into<String>, key: &DataValue) -> Result<()> {
        let tree = self.get_custom_tree(tree)?;
        self.delete_from_disk_with_encrypted_key(&tree, &key.to_bytes())?;
        Ok(())
    }

    // Retrieve a custom data in the selected format
    pub fn get_custom_data(&self, tree: impl Into<String>, key: &DataValue) -> Result<DataElement> {
        let tree = self.get_custom_tree(tree)?;
        self.load_from_disk_with_encrypted_key(&tree, &key.to_bytes())
    }

    // Verify if the key is present in the DB
    pub fn has_custom_data(&self, tree: impl Into<String>, key: &DataValue) -> Result<bool> {
        let tree = self.get_custom_tree(tree)?;
        self.contains_encrypted_data(&tree, &key.to_bytes())
    }

    // Search all entries with requested query_key/query_value
    // It has to go through the whole tree elements, decrypt each key/value and verify them against the query filter set
    pub fn query_db(&self, tree: impl Into<String>, query_key: Option<Query>, query_value: Option<Query>, return_on_first: bool) -> Result<QueryResult> {
        let tree = self.get_custom_tree(tree)?;
        let mut entries: IndexMap<DataValue, DataElement> = IndexMap::new();
        for res in tree.iter() {
            let (k, v) = res?;
            let mut key = None;
            let mut value = None;
            if let Some(query) = query_key.as_ref() {
                let decrypted = self.cipher.decrypt_value(&k)?;
                let k = DataValue::from_bytes(&decrypted)?;
                if !query.verify_value(&k) {
                    continue;
                }
                key = Some(k);
            }

            if let Some(query) = query_value.as_ref() {
                let decrypted = self.cipher.decrypt_value(&k)?;
                let v = DataElement::from_bytes(&decrypted)?;
                if !query.verify_element(&v) {
                    continue;
                }
                value = Some(v);
            }

            // Both query are accepted
            let key = if let Some(key) = key {
                key
            } else {
                let decrypted = self.cipher.decrypt_value(&k)?;
                DataValue::from_bytes(&decrypted)?
            };

            let value = if let Some(value) = value {
                value
            } else {
                let decrypted = self.cipher.decrypt_value(&v)?;
                DataElement::from_bytes(&decrypted)?
            };

            entries.insert(key, value);
            if return_on_first {
                break;
            }
        }

        Ok(QueryResult {
            entries,
            next: None
        })
    }

    // Get all keys from the custom
    pub fn get_custom_tree_keys(&self, tree: &String, query: &Option<Query>) -> Result<Vec<DataValue>> {
        let tree = self.get_custom_tree(tree)?;
        let mut keys = Vec::new();
        for e in tree.iter() {
            let (key, _) = e?;
            let decrypted = self.cipher.decrypt_value(&key)?;
            let k = DataValue::from_bytes(&decrypted)?;
            if let Some(query) = query {
                if !query.verify_value(&k) {
                    continue;
                }
            }
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

    // delete all transactions above the specified topoheight
    // This will go through each transaction, deserialize it, check topoheight, and delete it if required
    pub fn delete_transactions_above_topoheight(&mut self, topoheight: u64) -> Result<()> {
        for el in self.transactions.iter().values() {
            let value = el?;
            let entry = TransactionEntry::from_bytes(&self.cipher.decrypt_value(&value)?)?;
            if entry.get_topoheight() > topoheight {
                self.delete_transaction(entry.get_hash())?;
            }
        }

        Ok(())
    }

    // Filter when the data is deserialized to not load all transactions in memory
    pub fn get_filtered_transactions(&self, address: Option<&PublicKey>, min_topoheight: Option<u64>, max_topoheight: Option<u64>, accept_incoming: bool, accept_outgoing: bool, accept_coinbase: bool, accept_burn: bool, query: Option<&Query>) -> Result<Vec<TransactionEntry>> {
        let mut transactions = Vec::new();
        for el in self.transactions.iter().values() {
            let value = el?;
            let mut entry = TransactionEntry::from_bytes(&self.cipher.decrypt_value(&value)?)?;
            if let Some(topoheight) = min_topoheight {
                if entry.get_topoheight() < topoheight {
                    continue;
                }
            }
    
            if let Some(topoheight) = &max_topoheight {
                if entry.get_topoheight() > *topoheight {
                    continue;
                }
            }
    
            let (save, mut transfers) = match entry.get_mut_entry() {
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
                if let Some(query) = query {
                    if let Some(transfers) = transfers.as_mut() {
                        transfers.retain(|transfer| {
                            if let Some(element) = transfer.get_extra_data() {
                                query.verify_element(element)
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
                        transactions.push(entry);
                    },
                    // Something else than outgoing/incoming txs
                    None => {
                        transactions.push(entry);
                    },
                    // All the left is discarded
                    _ => {}
                }
            }
        }

        Ok(transactions)
    }

    // Delete a transaction saved in wallet using its hash
    pub fn delete_transaction(&mut self, hash: &Hash) -> Result<()> {
        self.transactions.remove(self.cipher.hash_key(hash.as_bytes()))?;
        Ok(())
    }

    // Delete all transactions from this wallet
    pub fn delete_transactions(&mut self) -> Result<()> {
        self.transactions.clear()?;
        Ok(())
    }

    // Delete all balances from this wallet
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

    // Check if the transaction is stored in wallet
    pub fn has_transaction(&self, hash: &Hash) -> Result<bool> {
        self.contains_data(&self.transactions, hash.as_bytes())
    }

    // Retrieve the nonce used to create new transactions
    pub fn get_nonce(&self) -> Result<u64> {
        self.load_from_disk(&self.extra, NONCE_KEY)
    }

    // Set the new nonce uised to create new transactions
    pub fn set_nonce(&mut self, nonce: u64) -> Result<()> {
        self.save_to_disk(&self.extra, NONCE_KEY, &nonce.to_be_bytes())
    }

    // Store the keypair
    pub fn set_keypair(&mut self, keypair: &KeyPair) -> Result<()> {
        self.save_to_disk(&self.extra, KEY_PAIR, &keypair.to_bytes())
    }

    // Retrieve the keypair of this wallet
    pub fn get_keypair(&self) -> Result<KeyPair> {
        self.load_from_disk(&self.extra, KEY_PAIR)
    }

    // Set the topoheight until which the wallet is synchronized
    pub fn set_synced_topoheight(&mut self, topoheight: u64) -> Result<()> {
        self.save_to_disk(&self.extra, TOPOHEIGHT_KEY, &topoheight.to_be_bytes())
    }

    // Get the topoheight until which the wallet is synchronized
    pub fn get_synced_topoheight(&self) -> Result<u64> {
        self.load_from_disk(&self.extra, TOPOHEIGHT_KEY)
    }

    // Delete the top block hash
    pub fn delete_top_block_hash(&mut self) -> Result<()> {
        self.delete_from_disk(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    // Set the top block hash until which the wallet is synchronized
    pub fn set_top_block_hash(&mut self, hash: &Hash) -> Result<()> {
        self.save_to_disk(&self.extra, TOP_BLOCK_HASH_KEY, hash.as_bytes())
    }

    // Check if a top block hash is set 
    pub fn has_top_block_hash(&self) -> Result<bool> {
        self.contains_data(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    // Top block hash until which the wallet is synchronized 
    pub fn get_top_block_hash(&self) -> Result<Hash> {
        self.load_from_disk(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    pub fn get_public_storage(&self) -> &Storage {
        &self.inner
    }

    pub fn get_mutable_public_storage(&mut self) -> &mut Storage {
        &mut self.inner
    }

    // Get the network on which this wallet is
    fn get_network(&self) -> Result<Network> {
        self.load_from_disk(&self.extra, NETWORK)
    }

    // Save the network to disk
    fn set_network(&mut self, network: &Network) -> Result<()> {
        self.save_to_disk(&self.extra, NETWORK, &network.to_bytes())
    }

    // Check if the network is already registered
    fn has_network(&self) -> Result<bool> {
        self.contains_data(&self.extra, NETWORK)
    }

    // Add a topoheight where a change occured
    pub fn add_topoheight_to_changes(&mut self, topoheight: u64, block_hash: &Hash) -> Result<()> {
        self.save_to_disk_with_encrypted_key(&self.changes_topoheight, &topoheight.to_be_bytes(), block_hash.as_bytes())
    }

    // Get the block hash for the requested topoheight
    pub fn get_block_hash_for_topoheight(&self, topoheight: u64) -> Result<Hash> {
        self.load_from_disk_with_encrypted_key(&self.changes_topoheight, &topoheight.to_be_bytes())
    }

    // Check if the topoheight is present in the changes tree
    pub fn has_topoheight_in_changes(&self, topoheight: u64) -> Result<bool> {
        self.contains_encrypted_data(&self.changes_topoheight, &topoheight.to_be_bytes())
    }

    // Delete all changes above topoheight
    // This will returns true if a changes was deleted
    pub fn delete_changes_above_topoheight(&mut self, topoheight: u64) -> Result<bool> {
        let mut deleted = false;
        for res in self.changes_topoheight.iter().keys() {
            let key = res?;
            let raw = self.cipher.decrypt_value(&key).context("Error while decrypting key from disk")?;
            let topo = u64::from_bytes(&raw)?;
            if topo > topoheight {
                self.changes_topoheight.remove(key)?;
                deleted = true;
            }
        }

        Ok(deleted)
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

    // retrieve the encrypted form of the master key
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

    // set password salt used to derive the password-based key
    pub fn set_password_salt(&mut self, salt: &[u8]) -> Result<()> {
        self.db.insert(PASSWORD_SALT_KEY, salt)?;
        Ok(())
    }

    // retrieve password salt used to derive the password-based key
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

    // get the salt used for encrypted storage
    pub fn get_encrypted_storage_salt(&self) -> Result<Vec<u8>> {
        let values = self.db.get(SALT_KEY)?.context("encrypted salt for storage was not found")?;
        let mut encrypted_salt = Vec::with_capacity(values.len());
        encrypted_salt.extend_from_slice(&values);

        Ok(encrypted_salt)
    }

    // set the salt used for encrypted storage
    pub fn set_encrypted_storage_salt(&mut self, salt: &[u8]) -> Result<()> {
        self.db.insert(SALT_KEY, salt)?;
        Ok(())
    }
}