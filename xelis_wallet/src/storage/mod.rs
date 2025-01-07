mod backend;
mod types;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    num::NonZeroUsize
};
use indexmap::IndexMap;
use lru::LruCache;
use xelis_common::{
    api::{
        query::{
            Query,
            QueryResult
        },
        DataElement,
        DataValue
    },
    asset::AssetData,
    config::XELIS_ASSET,
    crypto::{
        elgamal::CompressedCiphertext,
        Hash,
        PrivateKey,
        PublicKey
    },
    network::Network,
    serializer::{
        Reader,
        Serializer,
    },
    tokio::sync::Mutex,
    transaction::TxVersion
};
use anyhow::{
    Context,
    Result,
    anyhow
};
use crate::{
    cipher::Cipher,
    config::SALT_SIZE,
    entry::{
        EntryData,
        TransactionEntry,
        Transfer
    },
    error::WalletError
};
use log::{trace, debug, error};

use backend::{Db, Tree};

pub use types::*;

// keys used to retrieve from storage
const NONCE_KEY: &[u8] = b"NONCE";
const SALT_KEY: &[u8] = b"SALT";
// Password + salt is necessary to decrypt master key
const PASSWORD_SALT_KEY: &[u8] = b"PSALT";
// Master key to encrypt/decrypt while interacting with the storage 
const MASTER_KEY: &[u8] = b"MKEY";
const PRIVATE_KEY: &[u8] = b"PKEY";

// const used for online mode
// represent the daemon topoheight
const TOPOHEIGHT_KEY: &[u8] = b"TOPH";
// represent the daemon top block hash
const TOP_BLOCK_HASH_KEY: &[u8] = b"TOPBH";
const NETWORK: &[u8] = b"NET";
// Last coinbase reward topoheight
const LCRT: &[u8] = b"LCRT";
// Key to store the multisig state
const MULTISIG: &[u8] = b"MSIG";
// TX version to determine which version of TX we need
const TX_VERSION: &[u8] = b"TXV";

// Default cache size
const DEFAULT_CACHE_SIZE: usize = 100;

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
    // The inner storage
    inner: Storage,
    // Caches
    balances_cache: Mutex<LruCache<Hash, Balance>>,
    // this cache is used to store unconfirmed balances
    // it is used to store the balance before the transaction is confirmed
    // so we can build several txs without having to wait for the confirmation
    // We store it in a VecDeque so for each TX we have an entry and can just retrieve it
    unconfirmed_balances_cache: Mutex<HashMap<Hash, VecDeque<Balance>>>,
    // Temporary TX Cache used to build ordered TXs
    tx_cache: Option<TxCache>,
    // Cache for the assets with their decimals
    assets_cache: Mutex<LruCache<Hash, AssetData>>,
    // Cache for the synced topoheight
    synced_topoheight: Option<u64>,
    // Topoheight of the last coinbase reward
    // This is used to determine if we should
    // use a stable balance or not
    last_coinbase_reward_topoheight: Option<u64>,
    // Transaction version to use
    tx_version: TxVersion
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
            inner,
            balances_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap())),
            unconfirmed_balances_cache: Mutex::new(HashMap::new()),
            tx_cache: None,
            assets_cache: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap())),
            synced_topoheight: None,
            last_coinbase_reward_topoheight: None,
            tx_version: TxVersion::V0
        };

        if storage.has_network()? {
            let storage_network = storage.get_network()?;
            if storage_network != network {
                return Err(anyhow!("Network mismatch for this wallet storage (stored: {})!", storage_network));
            }
        } else {
            storage.set_network(&network)?;
        }

        // Load one-time the last coinbase reward topoheight
        if storage.contains_data(&storage.extra, LCRT)? {
            storage.last_coinbase_reward_topoheight = Some(storage.load_from_disk(&storage.extra, LCRT)?);
        }

        // Load one-time the transaction version
        if storage.contains_data(&storage.extra, TX_VERSION)? {
            storage.tx_version = storage.load_from_disk(&storage.extra, TX_VERSION)?;
        }

        Ok(storage)
    }

    // Flush on disk to make sure it is saved
    pub fn flush(&mut self) -> Result<()> {
        trace!("Flushing storage");
        self.inner.db.flush()?;
        Ok(())
    }

    // Await for the storage to be flushed
    pub async fn stop(&mut self) {
        trace!("Stopping storage");
        if let Err(e) = self.inner.db.flush_async().await {
            error!("Error while flushing the database: {}", e);
        }
    }

    // Key must be hashed or encrypted before calling this function
    fn internal_load<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<Option<V>> {
        trace!("internal load");
        let data = tree.get(key)?;
        Ok(match data {
            Some(data) => {
                let bytes = self.cipher.decrypt_value(&data).context("Error while decrypting value from disk")?;
                Some(V::from_bytes(&bytes).context("Error while de-serializing value from disk")?)
            },
            None => None
        })
    }

    // load from disk using a hashed key, decrypt the value and deserialize it
    fn load_from_disk_optional<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<Option<V>> {
        trace!("load from disk optional");
        let hashed_key = self.cipher.hash_key(key);
        self.internal_load(tree, &hashed_key)
    }

    // load from disk using a hashed key, decrypt the value and deserialize it
    fn load_from_disk<V: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<V> {
        trace!("load from disk");
        self.load_from_disk_optional(tree, key)?
            .context(format!("Error while loading data with hashed key {} from disk", String::from_utf8_lossy(key)))
    }

    // Because we can't predict the nonce used for encryption, we make it determistic
    fn create_encrypted_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        trace!("create encrypted key");
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
        trace!("load from disk with encrypted key");
        let encrypted_key = self.create_encrypted_key(key)?;
        self.internal_load(tree, &encrypted_key)?
            .context(format!("Error while loading data with encrypted key {} from disk", String::from_utf8_lossy(key)))
    }

    // Encrypt key, encrypt data and then save to disk
    // We encrypt instead of hashing to be able to retrieve the key
    fn save_to_disk_with_encrypted_key(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<()> {
        trace!("save to disk with encrypted key");
        let encrypted_key = self.create_encrypted_key(key)?;
        let encrypted_value = self.cipher.encrypt_value(value)?;
        tree.insert(encrypted_key, encrypted_value)?;
        Ok(())
    }

    // hash key, encrypt data and then save to disk 
    fn save_to_disk(&self, tree: &Tree, key: &[u8], value: &[u8]) -> Result<()> {
        trace!("save to disk");
        let hashed_key = self.cipher.hash_key(key);
        tree.insert(hashed_key, self.cipher.encrypt_value(value)?)?;
        Ok(())
    }

    // hash key, encrypt data and then save to disk 
    fn delete_from_disk(&self, tree: &Tree, key: &[u8]) -> Result<()> {
        trace!("delete from disk");
        let hashed_key = self.cipher.hash_key(key);
        tree.remove(hashed_key)?;
        Ok(())
    }

    // hash key, encrypt data and then save to disk 
    fn delete_from_disk_with_encrypted_key(&self, tree: &Tree, key: &[u8]) -> Result<()> {
        trace!("delete from disk with encrypted key");
        let encrypted_key = self.create_encrypted_key(key)?;
        tree.remove(encrypted_key)?;
        Ok(())
    }

    // Search if the data is present in the tree using hashed key
    fn contains_data(&self, tree: &Tree, key: &[u8]) -> Result<bool> {
        trace!("contains data");
        let hashed_key = self.cipher.hash_key(key);
        Ok(tree.contains_key(hashed_key)?)
    }

    // Encrypt instead of hash the key to recover it later
    fn contains_encrypted_data(&self, tree: &Tree, key: &[u8]) -> Result<bool> {
        trace!("contains encrypted data");
        let encrypted_key = self.create_encrypted_key(key)?;
        Ok(tree.contains_key(encrypted_key)?)
    }

    // Open the named tree
    fn get_custom_tree(&self, name: impl Into<String>) -> Result<Tree> {
        trace!("get custom tree");
        let hash = self.cipher.hash_key(format!("custom_{}", name.into()));
        let tree = self.inner.db.open_tree(&hash)?;
        Ok(tree)
    }

    // Clear all entries from the custom tree
    pub fn clear_custom_tree(&mut self, name: impl Into<String>) -> Result<()> {
        trace!("clear custom tree");
        let tree = self.get_custom_tree(name)?;
        tree.clear()?;
        Ok(())
    }

    // Store a custom serializable data 
    pub fn set_custom_data(&mut self, tree: impl Into<String>, key: &DataValue, value: &DataElement) -> Result<()> {
        trace!("set custom data");
        let tree = self.get_custom_tree(tree)?;
        self.save_to_disk_with_encrypted_key(&tree, &key.to_bytes(), &value.to_bytes())?;
        Ok(())
    }

    // Delete a custom data using its key 
    pub fn delete_custom_data(&mut self, tree: impl Into<String>, key: &DataValue) -> Result<()> {
        trace!("delete custom data");
        let tree = self.get_custom_tree(tree)?;
        self.delete_from_disk_with_encrypted_key(&tree, &key.to_bytes())?;
        Ok(())
    }

    // Retrieve a custom data in the selected format
    pub fn get_custom_data(&self, tree: impl Into<String>, key: &DataValue) -> Result<DataElement> {
        trace!("get custom data");
        let tree = self.get_custom_tree(tree)?;
        self.load_from_disk_with_encrypted_key(&tree, &key.to_bytes())
    }

    // Verify if the key is present in the DB
    pub fn has_custom_data(&self, tree: impl Into<String>, key: &DataValue) -> Result<bool> {
        trace!("has custom data");
        let tree = self.get_custom_tree(tree)?;
        self.contains_encrypted_data(&tree, &key.to_bytes())
    }

    // Search all entries with requested query_key/query_value
    // It has to go through the whole tree elements, decrypt each key/value and verify them against the query filter set
    pub fn query_db(&self, tree: impl Into<String>, query_key: Option<Query>, query_value: Option<Query>, return_on_first: bool) -> Result<QueryResult> {
        trace!("query db");
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
                let decrypted = self.cipher.decrypt_value(&v)?;
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
        trace!("get custom tree keys");
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

    // Count entries from a tree
    // A query is possible to filter on keys
    pub fn count_custom_tree_entries(&self, tree: &String, query_key: &Option<Query>, query_value: &Option<Query>) -> Result<usize> {
        trace!("count custom tree entries");
        let tree = self.get_custom_tree(tree)?;
        let count = if query_key.is_some() || query_value.is_some() {
            let mut count = 0;
            for res in tree.iter() {
                let (k, v) = res?;
                if let Some(query) = query_key {
                    let decrypted_key = self.cipher.decrypt_value(&k)?;
                    let key = DataValue::from_bytes(&decrypted_key)?;

                    if !query.verify_value(&key) {
                        continue;
                    }
                }

                if let Some(query) = query_value {
                    let decrypted_value = self.cipher.decrypt_value(&v)?;
                    let value = DataElement::from_bytes(&decrypted_value)?;

                    if !query.verify_element(&value) {
                        continue;
                    }
                }
                count += 1;
            }

            count
        } else {
            tree.len()
        };

        Ok(count)
    }

    // Set a multisig state
    pub async fn set_multisig_state(&mut self, state: MultiSig) -> Result<()> {
        trace!("set multisig state");
        self.save_to_disk(&self.extra, MULTISIG, &state.to_bytes())?;
        Ok(())
    }

    // Delete the multisig state
    pub async fn delete_multisig_state(&mut self) -> Result<()> {
        trace!("delete multisig state");
        self.delete_from_disk(&self.extra, MULTISIG)?;
        Ok(())
    }

    // Get the multisig state
    pub async fn get_multisig_state(&self) -> Result<Option<MultiSig>> {
        trace!("get multisig state");
        if !self.contains_data(&self.extra, MULTISIG)? {
            return Ok(None);
        }

        let state: MultiSig = self.load_from_disk(&self.extra, MULTISIG)?;
        Ok(Some(state))
    }

    // Check if the wallet has a multisig state
    pub async fn has_multi_sig_state(&self) -> Result<bool> {
        trace!("has multisig state");
        self.contains_data(&self.extra, MULTISIG)
    }

    // Set the TX Version
    pub async fn set_tx_version(&mut self, version: TxVersion) -> Result<()> {
        trace!("set tx version");
        self.save_to_disk(&self.extra, TX_VERSION, &version.to_bytes())?;
        self.tx_version = version;
        Ok(())
    }

    // Get the TX Version
    pub async fn get_tx_version(&self) -> Result<TxVersion> {
        trace!("get tx version");
        Ok(self.tx_version)
    }

    // this function is specific because we save the key in encrypted form (and not hashed as others)
    // returns all saved assets
    pub async fn get_assets(&self) -> Result<HashSet<Hash>> {
        trace!("get assets");
        let mut cache = self.assets_cache.lock().await;

        if cache.len() == self.assets.len() {
            return Ok(cache.iter().map(|(k, _)| k.clone()).collect());
        }

        let mut assets = HashSet::new();
        for res in self.assets.iter() {
            let (key, value) = res?;
            let raw_key = &self.cipher.decrypt_value(&key)?;
            let mut reader = Reader::new(raw_key);
            let asset = Hash::read(&mut reader)?;

            if !cache.contains(&asset) {
                let raw_value = &self.cipher.decrypt_value(&value)?;
                let mut reader = Reader::new(raw_value);
                let a = AssetData::read(&mut reader)?;
                cache.put(asset.clone(), a);
            }

            assets.insert(asset);
        }

        Ok(assets)
    }

    // Retrieve all assets with their data
    pub async fn get_assets_with_data(&self) -> Result<IndexMap<Hash, AssetData>> {
        trace!("get assets with decimals");
        let mut cache = self.assets_cache.lock().await;
        if cache.len() == self.assets.len() {
            return Ok(cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        }

        let mut assets = IndexMap::new();
        for res in self.assets.iter() {
            let (key, value) = res?;
            let asset = Hash::from_bytes(&self.cipher.decrypt_value(&key)?)?;
            let data = if let Some(asset) = cache.get(&asset) {
                asset.clone()
            } else {
                let raw_value = &self.cipher.decrypt_value(&value)?;
                let mut reader = Reader::new(raw_value);
                let data = AssetData::read(&mut reader)?;
                if cache.cap().get() != cache.len() {
                    cache.put(asset.clone(), data.clone());
                }

                data
            };

            assets.insert(asset, data);
        }

        Ok(assets)
    }

    // Check if the asset is already registered
    pub async fn contains_asset(&self, asset: &Hash) -> Result<bool> {
        trace!("contains asset");
        {
            let cache = self.assets_cache.lock().await;
            if cache.contains(asset) {
                return Ok(true);
            }
        }

        self.contains_encrypted_data(&self.assets, asset.as_bytes())
    }

    // save asset with its corresponding decimals
    pub async fn add_asset(&mut self, asset: &Hash, data: AssetData) -> Result<()> {
        trace!("add asset");
        if self.contains_asset(asset).await? {
            return Err(WalletError::AssetAlreadyRegistered.into());
        }

        self.save_to_disk_with_encrypted_key(&self.assets, asset.as_bytes(), &data.to_bytes())?;

        let mut cache = self.assets_cache.lock().await;
        cache.put(asset.clone(), data);
        Ok(())
    }

    // Retrieve the stored decimals for this asset for better display
    pub async fn get_asset(&self, asset: &Hash) -> Result<AssetData> {
        trace!("get asset");
        let mut cache = self.assets_cache.lock().await;
        if let Some(asset) = cache.get(asset) {
            return Ok(asset.clone());
        }

        let data: AssetData = self.load_from_disk_with_encrypted_key(&self.assets, asset.as_bytes())?;
        cache.put(asset.clone(), data.clone());

        Ok(data)
    }

    // Set the asset name
    pub async fn set_asset_name(&mut self, asset: &Hash, name: String) -> Result<()> {
        trace!("set asset name");
        let mut cache = self.assets_cache.lock().await;
        if let Some(asset) = cache.get_mut(asset) {
            asset.set_name(name.clone());
        }

        let data: AssetData = self.load_from_disk_with_encrypted_key(&self.assets, asset.as_bytes())?;
        let mut data = data;
        data.set_name(name);
        self.save_to_disk_with_encrypted_key(&self.assets, asset.as_bytes(), &data.to_bytes())?;
        Ok(())
    }

    // Retrieve the plaintext balance for this asset
    pub async fn get_plaintext_balance_for(&self, asset: &Hash) -> Result<u64> {
        trace!("get plaintext balance for {}", asset);
        let mut cache = self.balances_cache.lock().await;
        if let Some(balance) = cache.get(asset) {
            return Ok(balance.amount);
        }

        let balance: Balance = self.load_from_disk(&self.balances, asset.as_bytes())?;
        let plaintext_balance = balance.amount;
        cache.put(asset.clone(), balance);

        Ok(plaintext_balance)
    }

    // Retrieve the balance for this asset
    pub async fn get_balance_for(&self, asset: &Hash) -> Result<Balance> {
        trace!("get balance for {}", asset);
        let mut cache = self.balances_cache.lock().await;
        if let Some(balance) = cache.get(asset) {
            return Ok(balance.clone());
        }

        let balance: Balance = self.load_from_disk(&self.balances, asset.as_bytes())?;
        cache.put(asset.clone(), balance.clone());

        Ok(balance)
    }

    // Retrieve the unconfirmed balance for this asset if present
    // otherwise, fall back on the confirmed balance
    pub async fn get_unconfirmed_balance_for(&self, asset: &Hash) -> Result<(Balance, bool)> {
        trace!("get unconfirmed balance for {}", asset);
        let cache = self.unconfirmed_balances_cache.lock().await;
        if let Some(balances) = cache.get(asset) {
            // get the latest unconfirmed balance
            if let Some(balance) = balances.back() {
                return Ok((balance.clone(), true));
            }
        }

        // Fallback
        self.get_balance_for(asset).await.map(|balance| (balance, false))
    }

    // Verify if we have any unconfirmed balance stored
    pub async fn has_unconfirmed_balance_for(&self, asset: &Hash) -> Result<bool> {
        trace!("has unconfirmed balance for {}", asset);
        let cache = self.unconfirmed_balances_cache.lock().await;
        if let Some(balances) = cache.get(asset) {
            return Ok(!balances.is_empty());
        }

        Ok(false)
    }

    // Retrieve the unconfirmed balance decoded for this asset if present
    pub async fn get_unconfirmed_balance_decoded_for(&self, asset: &Hash, compressed_ct: &CompressedCiphertext) -> Result<Option<u64>> {
        trace!("get unconfirmed balance decoded for {}", asset);
        let mut cache = self.unconfirmed_balances_cache.lock().await;
        if let Some(balances) = cache.get_mut(asset) {
            for balance in balances.iter_mut() {
                if *balance.ciphertext.compressed() == *compressed_ct {
                    return Ok(Some(balance.amount));
                }
            }
        }

        Ok(None)
    }

    // Set the unconfirmed balance for this asset
    pub async fn set_unconfirmed_balance_for(&self, asset: Hash, balance: Balance) -> Result<()> {
        trace!("set unconfirmed balance for {}", asset);
        let mut cache = self.unconfirmed_balances_cache.lock().await;
        let balances = cache.entry(asset).or_insert_with(VecDeque::new);
        balances.push_back(balance);

        Ok(())
    }

    // Determine if we have any balance stored
    pub async fn has_any_balance(&self) -> Result<bool> {
        trace!("has any balance");
        let cache = self.balances_cache.lock().await;
        if !cache.is_empty() {
            return Ok(true);
        }

        Ok(!self.balances.is_empty())
    }

    // Determine if we have a balance for this asset
    pub async fn has_balance_for(&self, asset: &Hash) -> Result<bool> {
        trace!("has balance for {}", asset);
        let cache = self.balances_cache.lock().await;
        if cache.contains(asset) {
            return Ok(true);
        }

        self.contains_data(&self.balances, asset.as_bytes())
    }

    // Set the balance for this asset
    pub async fn set_balance_for(&mut self, asset: &Hash, mut balance: Balance) -> Result<()> {
        trace!("set balance for {}", asset);
        // Clear the cache of all outdated balances
        // for this, we simply go through all versions available and delete them all until we find the one we are looking for
        // The unconfirmed balances cache may not work during front running
        // As we only scan the final balances for each asset, if we get any incoming TX, compressed balance
        // will be different and we will not be able to find the unconfirmed balance
        {
            let mut cache = self.unconfirmed_balances_cache.lock().await;
            let mut delete_entry = false;
            if let Some(balances) = cache.get_mut(asset) {
                while let Some(mut b) = balances.pop_front() {
                    if *b.ciphertext.compressed() == *balance.ciphertext.compressed() {
                        debug!("unconfirmed balance previously stored found for {}", asset);
                        break;
                    }

                    if balances.is_empty() && self.tx_cache.is_some() {
                        debug!("no matching unconfirmed balance found for asset {} but last TX still not processed, inject back", asset);
                        balances.push_front(b);
                        break;
                    }
                }
                delete_entry = balances.is_empty();
            }

            if delete_entry {
                debug!("no more unconfirmed balance cache for {}", asset);
                cache.remove(asset);

                // If we have no more unconfirmed balance, we can clean the last tx reference
                if cache.is_empty() {
                    debug!("no more unconfirmed balance cache, cleaning tx cache ({:?})", self.tx_cache);
                    self.tx_cache = None;
                }
            }
        }

        self.save_to_disk(&self.balances, asset.as_bytes(), &balance.to_bytes())?;

        let mut cache = self.balances_cache.lock().await;
        cache.put(asset.clone(), balance);
        Ok(())
    }

    // Retrieve a transaction saved in wallet using its hash
    pub fn get_transaction(&self, hash: &Hash) -> Result<TransactionEntry> {
        trace!("get transaction {}", hash);
        self.load_from_disk(&self.transactions, hash.as_bytes())
    }

    // read whole disk and returns all transactions
    pub fn get_transactions(&self) -> Result<Vec<TransactionEntry>> {
        trace!("get transactions");
        self.get_filtered_transactions(None, None, None, None, true, true, true, true, None)
    }

    // Find the last outgoing transaction created
    pub fn get_last_outgoing_transaction(&self) -> Result<Option<TransactionEntry>> {
        trace!("get last transaction created");
        let mut last_tx: Option<TransactionEntry> = None;
        for res in self.transactions.iter().values() {
            let value = res?;
            let entry = TransactionEntry::from_bytes(&self.cipher.decrypt_value(&value)?)?;
            if !entry.is_outgoing() {
                continue;
            }

            if let Some(last) = last_tx.as_ref() {
                if entry.get_topoheight() > last.get_topoheight() {
                    last_tx = Some(entry);
                }
            } else {
                last_tx = Some(entry);
            }
        }

        Ok(last_tx)
    }

    // delete all transactions above the specified topoheight
    // This will go through each transaction, deserialize it, check topoheight, and delete it if required
    pub fn delete_transactions_above_topoheight(&mut self, topoheight: u64) -> Result<()> {
        trace!("delete transactions above topoheight {}", topoheight);
        for el in self.transactions.iter().values() {
            let value = el?;
            let entry = TransactionEntry::from_bytes(&self.cipher.decrypt_value(&value)?)?;
            if entry.get_topoheight() > topoheight {
                self.delete_transaction(entry.get_hash())?;
            }
        }

        Ok(())
    }

    // delete all transactions at or above the specified topoheight
    pub fn delete_transactions_at_or_above_topoheight(&mut self, topoheight: u64) -> Result<()> {
        trace!("delete transactions at or above topoheight {}", topoheight);
        for el in self.transactions.iter().values() {
            let value = el?;
            let entry = TransactionEntry::from_bytes(&self.cipher.decrypt_value(&value)?)?;
            if entry.get_topoheight() >= topoheight {
                self.delete_transaction(entry.get_hash())?;
            }
        }

        Ok(())
    }

    // delete all transactions at the specified topoheight
    // This will go through each transaction, deserialize it, check topoheight, and delete it if required
    // Maybe we can optimize it by keeping a lookuptable of topoheight -> txs ?
    pub fn delete_transactions_at_topoheight(&mut self, topoheight: u64) -> Result<()> {
        trace!("delete transactions at topoheight {}", topoheight);
        for el in self.transactions.iter().values() {
            let value = el?;
            let entry = TransactionEntry::from_bytes(&self.cipher.decrypt_value(&value)?)?;
            if entry.get_topoheight() == topoheight {
                self.delete_transaction(entry.get_hash())?;
            }
        }

        Ok(())
    }

    // Filter when the data is deserialized to not load all transactions in memory
    pub fn get_filtered_transactions(&self, address: Option<&PublicKey>, asset: Option<&Hash>, min_topoheight: Option<u64>, max_topoheight: Option<u64>, accept_incoming: bool, accept_outgoing: bool, accept_coinbase: bool, accept_burn: bool, query: Option<&Query>) -> Result<Vec<TransactionEntry>> {
        trace!("get filtered transactions");
        let mut transactions = Vec::new();
        for el in self.transactions.iter().values() {
            let value = el?;
            let mut entry = TransactionEntry::from_bytes(&self.cipher.decrypt_value(&value)?)?;
            trace!("entry: {}", entry.get_hash());
            if let Some(topoheight) = min_topoheight {
                if entry.get_topoheight() < topoheight {
                    trace!("entry topoheight {} < min topoheight {}", entry.get_topoheight(), topoheight);
                    continue;
                }
            }

            if let Some(topoheight) = max_topoheight {
                if entry.get_topoheight() > topoheight {
                    trace!("entry topoheight {} > max topoheight {}", entry.get_topoheight(), topoheight);
                    continue;
                }
            }

            let mut transfers: Option<Vec<Transfer>> = None;
            match entry.get_mut_entry() {
                EntryData::Coinbase { .. } if accept_coinbase && (asset.map(|a| *a == XELIS_ASSET).unwrap_or(true)) => {},
                EntryData::Burn { asset: burn_asset, .. } if accept_burn => {
                    if let Some(asset) = asset {
                        if *asset != *burn_asset {
                            trace!("entry burn asset {} != requested asset {}", burn_asset, asset);
                            continue;
                        }
                    }
                },
                EntryData::Incoming { from, transfers: t } if accept_incoming => {
                    // Filter by address
                    if let Some(filter_key) = address {
                        if *from != *filter_key {
                            trace!("entry from != requested address");
                            continue;
                        }
                    }

                    // Filter by asset
                    if let Some(asset) = asset {
                        t.retain(|transfer| *transfer.get_asset() == *asset);
                    }

                    transfers = Some(t.iter_mut().map(|t| Transfer::In(t)).collect());
                },
                EntryData::Outgoing { transfers: t, .. } if accept_outgoing => {
                    // Filter by address
                    if let Some(filter_key) = address {
                        t.retain(|transfer| *transfer.get_destination() == *filter_key);
                    }

                    // Filter by asset
                    if let Some(asset) = asset {
                        t.retain(|transfer| *transfer.get_asset() == *asset);
                    }

                    transfers = Some(t.iter_mut().map(|t| Transfer::Out(t)).collect());
                },
                EntryData::MultiSig { participants, .. } if accept_outgoing => {
                    // Filter by address
                    if let Some(filter_key) = address {
                        if !participants.contains(filter_key) {
                            continue;
                        }
                    }
                },
                EntryData::InvokeContract { deposits, .. } if accept_outgoing => {
                    // Filter by asset
                    if let Some(asset) = asset {
                        if !deposits.contains_key(asset) {
                            continue;
                        }

                        deposits.retain(|deposit, _| *deposit == *asset);
                    }
                },
                EntryData::DeployContract { .. } if accept_outgoing => {},
                _ => continue,
            };

            // Check if it has requested extra data
            if let Some(query) = query {
                if let Some(transfers) = transfers.as_mut() {
                    transfers.retain(|transfer| {
                        if let Some(element) = transfer.get_extra_data() {
                            query.verify_element(element.data())
                        } else {
                            false
                        }
                    });
                } else {
                    // Coinbase, burn, etc will be discarded always with such filter
                    trace!("entry has no extra data, discarding");
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
                e => {
                    trace!("entry has no transfers, discarding {:?}", e);
                }
            }
        }

        Ok(transactions)
    }

    // Delete a transaction saved in wallet using its hash
    pub fn delete_transaction(&mut self, hash: &Hash) -> Result<()> {
        trace!("delete transaction {}", hash);
        self.transactions.remove(self.cipher.hash_key(hash.as_bytes()))?;
        Ok(())
    }

    // Delete all transactions from this wallet
    pub fn delete_transactions(&mut self) -> Result<()> {
        trace!("delete transactions");
        self.transactions.clear()?;
        Ok(())
    }

    // Delete all balances from this wallet
    pub async fn delete_balances(&mut self) -> Result<()> {
        trace!("delete balances");
        self.balances.clear()?;
        self.delete_unconfirmed_balances().await;
        self.balances_cache.lock().await.clear();
        Ok(())
    }

    // Delete all unconfirmed balances from this wallet
    pub async fn delete_unconfirmed_balances(&mut self) {
        trace!("delete unconfirmed balances");
        self.unconfirmed_balances_cache.lock().await.clear();
        self.clear_tx_cache();
    }

    // Delete tx cache
    pub fn clear_tx_cache(&mut self) {
        trace!("clear tx cache");
        self.tx_cache = None;
    }

    // Delete all assets from this wallet
    pub async fn delete_assets(&mut self) -> Result<()> {
        trace!("delete assets");
        self.assets.clear()?;
        self.assets_cache.lock().await.clear();
        Ok(())
    }

    // Save the transaction with its TX hash as key
    // We hash the hash of the TX to use it as a key to not let anyone being able to see txs saved on disk
    // with no access to the decrypted master key
    pub fn save_transaction(&mut self, hash: &Hash, transaction: &TransactionEntry) -> Result<()> {
        trace!("save transaction {}", hash);

        if self.tx_cache.as_ref().is_some_and(|c| c.last_tx_hash_created.as_ref() == Some(hash)) {
            debug!("Transaction {} has been executed, deleting cache", hash);
            self.tx_cache = None;
        }

        self.save_to_disk(&self.transactions, hash.as_bytes(), &transaction.to_bytes())
    }

    // Check if the transaction is stored in wallet
    pub fn has_transaction(&self, hash: &Hash) -> Result<bool> {
        trace!("has transaction {}", hash);
        self.contains_data(&self.transactions, hash.as_bytes())
    }

    // Retrieve the nonce used to create new transactions
    pub fn get_nonce(&self) -> Result<u64> {
        trace!("get nonce");
        Ok(self.load_from_disk_optional(&self.extra, NONCE_KEY)?
            .unwrap_or(0))
    }

    // Get the unconfirmed nonce to use to build ordered TXs
    // It will fallback to the real nonce if not set
    pub fn get_unconfirmed_nonce(&self) -> u64 {
        trace!("get unconfirmed nonce");
        self.tx_cache.as_ref().map(|c| c.nonce).unwrap_or_else(|| self.get_nonce().unwrap_or(0))
    }

    // Set the TX cache to use it has reference for next txs
    pub fn set_tx_cache(&mut self, tx_cache: TxCache) {
        trace!("set tx cache");
        self.tx_cache = Some(tx_cache);
    }

    // Get the TX Cache used to build ordered TX
    pub fn get_tx_cache(&self) -> Option<&TxCache> {
        trace!("get tx cache");
        self.tx_cache.as_ref()
    }

    // Set the new nonce used to create new transactions
    // If the unconfirmed nonce is lower than the new nonce, we reset it
    pub fn set_nonce(&mut self, nonce: u64) -> Result<()> {
        trace!("set nonce to {}", nonce);
        self.save_to_disk(&self.extra, NONCE_KEY, &nonce.to_be_bytes())
    }

    // Store the last coinbase reward topoheight
    // This is used to determine if we should use a stable balance or not
    pub fn set_last_coinbase_reward_topoheight(&mut self, topoheight: Option<u64>) -> Result<()> {
        trace!("set last coinbase reward topoheight to {:?}", topoheight);
        if let Some(topoheight) = topoheight {
            if let Some(last_topo) = self.last_coinbase_reward_topoheight.filter(|v| *v > topoheight) {
                debug!("last coinbase reward topoheight ({}) already set to a higher value ({}), ignoring", topoheight, last_topo);
                return Ok(());
            }

            self.save_to_disk(&self.extra, LCRT, &topoheight.to_be_bytes())?;
        } else {
            self.delete_from_disk(&self.extra, LCRT)?;
        }

        self.last_coinbase_reward_topoheight = topoheight;
        Ok(())
    }

    // Get the last coinbase reward topoheight
    pub fn get_last_coinbase_reward_topoheight(&self) -> Option<u64> {
        trace!("get last coinbase reward topoheight");
        self.last_coinbase_reward_topoheight
    }

    // Store the private key
    pub fn set_private_key(&mut self, private_key: &PrivateKey) -> Result<()> {
        trace!("set private key");
        self.save_to_disk(&self.extra, PRIVATE_KEY, &private_key.to_bytes())
    }

    // Retrieve the keypair of this wallet
    pub fn get_private_key(&self) -> Result<PrivateKey> {
        trace!("get private key");
        self.load_from_disk(&self.extra, PRIVATE_KEY)
    }

    // Set the topoheight until which the wallet is synchronized
    pub fn set_synced_topoheight(&mut self, topoheight: u64) -> Result<()> {
        trace!("set synced topoheight to {}", topoheight);
        self.synced_topoheight = Some(topoheight);
        self.save_to_disk(&self.extra, TOPOHEIGHT_KEY, &topoheight.to_be_bytes())
    }

    // Get the topoheight until which the wallet is synchronized
    pub fn get_synced_topoheight(&self) -> Result<u64> {
        trace!("get synced topoheight");

        if let Some(topoheight) = self.synced_topoheight {
            trace!("returning cached synced topoheight {}", topoheight);
            return Ok(topoheight);
        }

        let synced_topoheight = self.load_from_disk(&self.extra, TOPOHEIGHT_KEY)?;
        Ok(synced_topoheight)
    }

    // Delete the top block hash
    pub fn delete_top_block_hash(&mut self) -> Result<()> {
        trace!("delete top block hash");
        self.delete_from_disk(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    // Set the top block hash until which the wallet is synchronized
    pub fn set_top_block_hash(&mut self, hash: &Hash) -> Result<()> {
        trace!("set top block hash to {}", hash);
        self.save_to_disk(&self.extra, TOP_BLOCK_HASH_KEY, hash.as_bytes())
    }

    // Check if a top block hash is set 
    pub fn has_top_block_hash(&self) -> Result<bool> {
        trace!("has top block hash");
        self.contains_data(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    // Top block hash until which the wallet is synchronized 
    pub fn get_top_block_hash(&self) -> Result<Hash> {
        trace!("get top block hash");
        self.load_from_disk(&self.extra, TOP_BLOCK_HASH_KEY)
    }

    pub fn get_public_storage(&self) -> &Storage {
        trace!("get public storage");
        &self.inner
    }

    pub fn get_mutable_public_storage(&mut self) -> &mut Storage {
        trace!("get mutable public storage");
        &mut self.inner
    }

    // Get the network on which this wallet is
    fn get_network(&self) -> Result<Network> {
        trace!("get network");
        self.load_from_disk(&self.extra, NETWORK)
    }

    // Save the network to disk
    fn set_network(&mut self, network: &Network) -> Result<()> {
        trace!("set network to {}", network);
        self.save_to_disk(&self.extra, NETWORK, &network.to_bytes())
    }

    // Check if the network is already registered
    fn has_network(&self) -> Result<bool> {
        trace!("has network");
        self.contains_data(&self.extra, NETWORK)
    }

    // Add a topoheight where a change occured
    pub fn add_topoheight_to_changes(&mut self, topoheight: u64, block_hash: &Hash) -> Result<()> {
        trace!("add topoheight to changes: {} at {}", topoheight, block_hash);
        self.save_to_disk_with_encrypted_key(&self.changes_topoheight, &topoheight.to_be_bytes(), block_hash.as_bytes())
    }

    // Get the block hash for the requested topoheight
    pub fn get_block_hash_for_topoheight(&self, topoheight: u64) -> Result<Hash> {
        trace!("get block hash for topoheight {}", topoheight);
        self.load_from_disk_with_encrypted_key(&self.changes_topoheight, &topoheight.to_be_bytes())
    }

    // Check if the topoheight is present in the changes tree
    pub fn has_topoheight_in_changes(&self, topoheight: u64) -> Result<bool> {
        trace!("has topoheight {} in changes", topoheight);
        self.contains_encrypted_data(&self.changes_topoheight, &topoheight.to_be_bytes())
    }

    // Delete all changes above topoheight
    // This will returns true if a changes was deleted
    pub fn delete_changes_above_topoheight(&mut self, topoheight: u64) -> Result<bool> {
        trace!("delete changes above topoheight {}", topoheight);
        let mut deleted = false;
        for res in self.changes_topoheight.iter().keys() {
            let key = res?;
            let raw = self.cipher.decrypt_value(&key).context("Error while decrypting key from disk")?;
            let topo = u64::from_bytes(&raw)?;
            if topo > topoheight {
                trace!("deleting topoheight changes at {}", topo);
                self.changes_topoheight.remove(key)?;
                deleted = true;
            }
        }

        Ok(deleted)
    }

    // Delete changes at topoheight
    // This will returns true if a changes was deleted
    pub fn delete_changes_at_topoheight(&mut self, topoheight: u64) -> Result<()> {
        trace!("delete changes at topoheight {}", topoheight);
        self.delete_from_disk_with_encrypted_key(&self.changes_topoheight, &topoheight.to_be_bytes())?;

        Ok(())
    }

    // Retrieve topoheight changes 
    pub fn get_topoheight_changes<'a>(&'a self) -> impl Iterator<Item = Result<(u64, Hash)>> + 'a {
        trace!("get topoheight changes");
        self.changes_topoheight.iter().rev().map(|res| {
            let (key, value) = res?;
            let topo = u64::from_bytes(&self.cipher.decrypt_value(&key)?)?;
            let hash = Hash::from_bytes(&self.cipher.decrypt_value(&value)?)?;
            Ok((topo, hash))
        })
    }

    // Find highest topoheight in changes
    pub fn get_highest_topoheight_in_changes_below(&self, max: u64) -> Result<u64> {
        trace!("get highest topoheight in changes below {}", max);
        let mut highest = 0;
        for res in self.changes_topoheight.iter().keys() {
            let key = res?;
            let raw = self.cipher.decrypt_value(&key).context("Error while decrypting key from disk")?;
            let topo = u64::from_bytes(&raw)?;
            if topo > highest && topo < max {
                highest = topo;
            }
        }

        Ok(highest)
    }
}

impl Storage {
    pub fn new(name: &str) -> Result<Self> {
        let db = backend::open(name)?;

        Ok(Self {
            db
        })
    }

    // save the encrypted form of the master key
    // it can only be decrypted using the password-based key
    pub fn set_encrypted_master_key(&mut self, encrypted_key: &[u8]) -> Result<()> {
        trace!("set encrypted master key");
        self.db.insert(MASTER_KEY, encrypted_key)?;
        Ok(())
    }

    // retrieve the encrypted form of the master key
    pub fn get_encrypted_master_key(&self) -> Result<Vec<u8>> {
        trace!("get encrypted master key");
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
        trace!("set password salt");
        self.db.insert(PASSWORD_SALT_KEY, salt)?;
        Ok(())
    }

    // retrieve password salt used to derive the password-based key
    pub fn get_password_salt(&self) -> Result<[u8; SALT_SIZE]> {
        trace!("get password salt");
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
        trace!("get encrypted storage salt");
        let values = self.db.get(SALT_KEY)?.context("encrypted salt for storage was not found")?;
        let mut encrypted_salt = Vec::with_capacity(values.len());
        encrypted_salt.extend_from_slice(&values);

        Ok(encrypted_salt)
    }

    // set the salt used for encrypted storage
    pub fn set_encrypted_storage_salt(&mut self, salt: &[u8]) -> Result<()> {
        trace!("set encrypted storage salt");
        self.db.insert(SALT_KEY, salt)?;
        Ok(())
    }
}