use anyhow::Context;
use async_trait::async_trait;
use indexmap::IndexSet;
use crate::{
    config::PRUNE_SAFETY_LIMIT,
    core::error::{BlockchainError, DiskContext}
};
use xelis_common::{
    account::{VersionedBalance, VersionedNonce},
    block::{Block, BlockHeader},
    crypto::{Hash, PublicKey},
    difficulty::{CumulativeDifficulty, Difficulty},
    immutable::Immutable,
    network::Network,
    serializer::{Reader, Serializer},
    transaction::Transaction
};
use std::{
    collections::HashSet,
    hash::Hash as StdHash,
    sync::{Arc, atomic::{AtomicU64, Ordering}},
    num::NonZeroUsize
};
use tokio::sync::Mutex;
use lru::LruCache;
use sled::Tree;
use log::{debug, trace, warn, info};

use super::{
    BalanceProvider,
    BlocksAtHeightProvider,
    DagOrderProvider,
    DifficultyProvider,
    NonceProvider,
    PrunedTopoheightProvider,
    ClientProtocolProvider,
    TransactionProvider,
    BlockProvider,
    Storage,
    Tips
};

// Constant keys used for extra Tree
const TIPS: &[u8; 4] = b"TIPS";
const TOP_TOPO_HEIGHT: &[u8; 4] = b"TOPO";
const TOP_HEIGHT: &[u8; 4] = b"TOPH";
const NETWORK: &[u8] = b"NET";
pub(super) const PRUNED_TOPOHEIGHT: &[u8; 4] = b"PRUN";
// Counters (prevent to perform a O(n))
pub(super) const ACCOUNTS_COUNT: &[u8; 4] = b"CACC";
pub(super) const TXS_COUNT: &[u8; 4] = b"CTXS";
const ASSETS_COUNT: &[u8; 4] = b"CAST";
pub(super) const BLOCKS_COUNT: &[u8; 4] = b"CBLK";

pub struct SledStorage {
    // Network used by the storage
    mainnet: bool,
    // All trees used to store data
    // all txs stored on disk
    pub(super) transactions: Tree,
    // all txs executed in block
    pub(super) txs_executed: Tree,
    // all blocks on disk
    pub(super) blocks: Tree,
    // all blocks height at specific height
    pub(super) blocks_at_height: Tree,
    // all extra data saved on disk
    pub(super) extra: Tree,
    // topo at hash on disk
    pub(super) topo_by_hash: Tree,
    // hash at topo height on disk
    pub(super) hash_at_topo: Tree,
    // cumulative difficulty for each block hash on disk
    pub(super) cumulative_difficulty: Tree,
    // Difficulty estimated covariance (P)
    pub(super) difficulty_covariance: Tree,
    // keep tracks of all available assets on network
    pub(super) assets: Tree,
    // account nonces to prevent TX replay attack
    pub(super) nonces: Tree,
    // block reward for each block topoheight
    pub(super) rewards: Tree,
    // supply for each block topoheight
    pub(super) supply: Tree,
    // difficulty for each block hash
    pub(super) difficulty: Tree,
    // tree to store all blocks hashes where a tx was included in 
    pub(super) tx_blocks: Tree,
    // Tree that store all versioned nonces using hashed keys
    pub(super) versioned_nonces: Tree,
    // Tree that store all balances with prefixed keys
    pub(super) balances: Tree,
    // Tree that store all versioned balances using hashed keys
    pub(super) versioned_balances: Tree,
    // Tree that store all merkle hashes for each topoheight
    pub(super) merkle_hashes: Tree,
    // Account registrations topoheight
    pub(super) registrations: Tree,
    // Account registrations prefixed by their topoheight for easier deletion
    pub(super) registrations_prefixed: Tree,
    // opened DB used for assets to create dynamic assets
    db: sled::Db,

    // all available caches
    // Transaction cache
    pub(super) transactions_cache: Option<Mutex<LruCache<Hash, Arc<Transaction>>>>,
    // Block header cache
    pub(super) blocks_cache: Option<Mutex<LruCache<Hash, Arc<BlockHeader>>>>,
    // Blocks Tips cache
    pub(super) past_blocks_cache: Option<Mutex<LruCache<Hash, Arc<IndexSet<Hash>>>>>,
    // Topoheight by hash cache
    pub(super) topo_by_hash_cache: Option<Mutex<LruCache<Hash, u64>>>,
    // Hash by topoheight cache
    pub(super) hash_at_topo_cache: Option<Mutex<LruCache<u64, Hash>>>,
    // Cumulative difficulty cache
    pub(super) cumulative_difficulty_cache: Option<Mutex<LruCache<Hash, CumulativeDifficulty>>>,
    // Assets cache
    pub(super) assets_cache: Option<Mutex<LruCache<Hash, ()>>>,
    // Balances Trees cache: keep opened trees in memory to prevent re-open
    balances_trees_cache: Option<Mutex<LruCache<(Hash, u64), Tree>>>,
    // Nonces Trees cache: keep opened trees in memory to prevent re-open
    nonces_trees_cache: Option<Mutex<LruCache<u64, Tree>>>,
    // Tips cache: current chain Tips
    tips_cache: Tips,
    // Pruned topoheight cache
    pub(super) pruned_topoheight: Option<u64>,

    // Atomic counters
    // Count of assets
    pub(super) assets_count: AtomicU64,
    // Count of accounts
    pub(super) accounts_count: AtomicU64,
    // Count of transactions
    pub(super) transactions_count: AtomicU64,
    // Count of blocks
    pub(super) blocks_count: AtomicU64
}

macro_rules! init_cache {
    ($cache_size: expr) => {{
        if let Some(size) = &$cache_size {
            Some(Mutex::new(LruCache::new(NonZeroUsize::new(*size).unwrap())))
        } else {
            None
        }
    }};
}

impl SledStorage {
    pub fn new(dir_path: String, cache_size: Option<usize>, network: Network) -> Result<Self, BlockchainError> {
        let sled = sled::open(format!("{}{}", dir_path, network.to_string().to_lowercase()))?;
        let mut storage = Self {
            mainnet: network.is_mainnet(),
            transactions: sled.open_tree("transactions")?,
            txs_executed: sled.open_tree("txs_executed")?,
            blocks: sled.open_tree("blocks")?,
            blocks_at_height: sled.open_tree("blocks_at_height")?,
            extra: sled.open_tree("extra")?,
            topo_by_hash: sled.open_tree("topo_at_hash")?,
            hash_at_topo: sled.open_tree("hash_at_topo")?,
            cumulative_difficulty: sled.open_tree("cumulative_difficulty")?,
            difficulty_covariance: sled.open_tree("difficulty_covariance")?,
            assets: sled.open_tree("assets")?,
            nonces: sled.open_tree("nonces")?,
            rewards: sled.open_tree("rewards")?,
            supply: sled.open_tree("supply")?,
            difficulty: sled.open_tree("difficulty")?,
            tx_blocks: sled.open_tree("tx_blocks")?,
            versioned_nonces: sled.open_tree("versioned_nonces")?,
            balances: sled.open_tree("balances")?,
            versioned_balances: sled.open_tree("versioned_balances")?,
            merkle_hashes: sled.open_tree("merkle_hashes")?,
            registrations: sled.open_tree("registrations")?,
            registrations_prefixed: sled.open_tree("registrations_prefixed")?,
            db: sled,
            transactions_cache: init_cache!(cache_size),
            blocks_cache: init_cache!(cache_size),
            past_blocks_cache: init_cache!(cache_size),
            topo_by_hash_cache: init_cache!(cache_size),
            hash_at_topo_cache: init_cache!(cache_size),
            cumulative_difficulty_cache: init_cache!(cache_size),
            assets_cache: init_cache!(cache_size),
            balances_trees_cache: init_cache!(cache_size),
            nonces_trees_cache: init_cache!(cache_size),
            tips_cache: HashSet::new(),
            pruned_topoheight: None,
            assets_count: AtomicU64::new(0),
            accounts_count: AtomicU64::new(0),
            transactions_count: AtomicU64::new(0),
            blocks_count: AtomicU64::new(0)
        };

        // Verify that we are opening a DB on same network
        // This prevent any corruption made by user
        if storage.has_network()? {
            let storage_network = storage.get_network()?;
            if storage_network != network {
                return Err(BlockchainError::InvalidNetwork);
            }
        } else {
            storage.set_network(&network)?;
        }

        // Load tips from disk if available
        if let Ok(tips) = storage.load_from_disk::<Tips>(&storage.extra, TIPS) {
            debug!("Found tips: {}", tips.len());
            storage.tips_cache = tips;
        }

        // Load the pruned topoheight from disk if available
        if let Ok(pruned_topoheight) = storage.load_from_disk::<u64>(&storage.extra, PRUNED_TOPOHEIGHT) {
            debug!("Found pruned topoheight: {}", pruned_topoheight);
            storage.pruned_topoheight = Some(pruned_topoheight);
        }

        // Load the assets count from disk if available
        if let Ok(assets_count) = storage.load_from_disk::<u64>(&storage.extra, ASSETS_COUNT) {
            debug!("Found assets count: {}", assets_count);
            storage.assets_count.store(assets_count, Ordering::SeqCst);
        }

        // Load the txs count from disk if available
        if let Ok(txs_count) = storage.load_from_disk::<u64>(&storage.extra, TXS_COUNT) {
            debug!("Found txs count: {}", txs_count);
            storage.transactions_count.store(txs_count, Ordering::SeqCst);
        }

        // Load the blocks count from disk if available
        if let Ok(blocks_count) = storage.load_from_disk::<u64>(&storage.extra, BLOCKS_COUNT) {
            debug!("Found blocks count: {}", blocks_count);
            storage.blocks_count.store(blocks_count, Ordering::SeqCst);
        }

        // Load the accounts count from disk if available
        if let Ok(accounts_count) = storage.load_from_disk::<u64>(&storage.extra, ACCOUNTS_COUNT) {
            debug!("Found accounts count: {}", accounts_count);
            storage.accounts_count.store(accounts_count, Ordering::SeqCst);
        }

        Ok(storage)
    }

    pub fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    pub(super) fn load_optional_from_disk<T: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<Option<T>, BlockchainError> {
        match tree.get(key)? {
            Some(bytes) => {
                let bytes = bytes.to_vec();
                let mut reader = Reader::new(&bytes);
                let value = T::read(&mut reader)?;
                Ok(Some(value))
            },
            None => Ok(None)
        }
    }

    pub(super) fn load_from_disk<T: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<T, BlockchainError> {
        match tree.get(key)? {
            Some(bytes) => {
                let bytes = bytes.to_vec();
                let mut reader = Reader::new(&bytes);
                let value = T::read(&mut reader)?;
                Ok(value)
            },
            None => Err(BlockchainError::NotFoundOnDisk(DiskContext::LoadData))
        }
    }

    pub(super) async fn get_cacheable_arc_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, Arc<V>>>>, key: &K) -> Result<Arc<V>, BlockchainError> {
        let value = if let Some(cache) = cache {
            let mut cache = cache.lock().await;
            if let Some(value) = cache.get(key) {
                return Ok(Arc::clone(&value));
            }

            let value = Arc::new(self.load_from_disk(tree, &key.to_bytes())?);
            cache.put(key.clone(), Arc::clone(&value));
            value
        } else {
            Arc::new(self.load_from_disk(tree, &key.to_bytes())?)
        };

        Ok(value)
    }

    pub(super) async fn get_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer + Clone>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<V, BlockchainError> {
        let value = if let Some(cache) = cache {
            let mut cache = cache.lock().await;
            if let Some(value) = cache.get(key) {
                return Ok(value.clone());
            }

            let value: V = self.load_from_disk(tree, &key.to_bytes())?;
            cache.put(key.clone(), value.clone());
            value
        } else {
            self.load_from_disk(tree, &key.to_bytes())?
        };

        Ok(value)
    }

    pub(super) async fn delete_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<V, BlockchainError> {
        let bytes = match tree.remove(key.to_bytes())? {
            Some(data) => data.to_vec(),
            None => return Err(BlockchainError::NotFoundOnDisk(DiskContext::DeleteData))
        };

        if let Some(cache) = cache {
            let mut cache = cache.lock().await;
            if let Some(value) = cache.pop(key) {
                return Ok(value);
            }
        }

        let mut reader = Reader::new(&bytes);
        let value = V::read(&mut reader)?;
        Ok(value)
    }

    pub(super) async fn delete_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, Arc<V>>>>, key: &K) -> Result<Arc<V>, BlockchainError> {
        let bytes = match tree.remove(key.to_bytes())? {
            Some(data) => data.to_vec(),
            None => return Err(BlockchainError::NotFoundOnDisk(DiskContext::DeleteData))
        };

        if let Some(cache) = cache {
            let mut cache = cache.lock().await;
            if let Some(value) = cache.pop(key) {
                return Ok(value);
            }
        }

        let mut reader = Reader::new(&bytes);
        let value = V::read(&mut reader)?;
        Ok(Arc::new(value))
    }

    pub(super) async fn contains_data<K: Eq + StdHash + Serializer + Clone, V>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<bool, BlockchainError> {
        if let Some(cache) = cache {
            let cache = cache.lock().await;
            return Ok(cache.contains(key) || tree.contains_key(&key.to_bytes())?)
        }

        Ok(tree.contains_key(&key.to_bytes())?)
    }

    // Update the assets count and store it on disk
    pub(super) fn store_assets_count(&self, count: u64) -> Result<(), BlockchainError> {
        self.assets_count.store(count, Ordering::SeqCst);
        self.extra.insert(ASSETS_COUNT, &count.to_be_bytes())?;
        Ok(())
    }

    fn delete_versioned_tree_above_topoheight(&self, tree: &Tree, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces above or at topoheight {}", topoheight);
        for el in tree.iter().keys() {
            let key = el?;
            let topo = u64::from_bytes(&key[0..8])?;
            if topo > topoheight {
                tree.remove(&key)?;
            }
        }
        Ok(())
    }

    fn delete_versioned_tree_below_topoheight(&self, tree: &Tree, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces above or at topoheight {}", topoheight);
        for el in tree.iter().keys() {
            let key = el?;
            let topo = u64::from_bytes(&key[0..8])?;
            if topo < topoheight {
                tree.remove(&key)?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Storage for SledStorage {
    fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    async fn clear_caches(&mut self) -> Result<(), BlockchainError> {
        if let Some(cache) = self.transactions_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.blocks_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.past_blocks_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.topo_by_hash_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.hash_at_topo_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.cumulative_difficulty_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.assets_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.balances_trees_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        if let Some(cache) = self.nonces_trees_cache.as_ref() {
            let mut cache = cache.lock().await;
            cache.clear();
        }

        Ok(())
    }

    // Delete the whole block using its topoheight
    async fn delete_block_at_topoheight(&mut self, topoheight: u64) -> Result<(Hash, Arc<BlockHeader>, Vec<(Hash, Arc<Transaction>)>), BlockchainError> {
        trace!("Delete block at topoheight {topoheight}");

        // delete topoheight<->hash pointers
        let hash = self.delete_cacheable_data(&self.hash_at_topo, &self.hash_at_topo_cache, &topoheight).await?;
        trace!("Hash is {hash} at topo {topoheight}");

        self.delete_cacheable_data::<Hash, u64>(&self.topo_by_hash, &self.topo_by_hash_cache, &hash).await?;

        trace!("deleting block header {}", hash);
        let block = self.delete_data(&self.blocks, &self.blocks_cache, &hash).await?;
        trace!("block header deleted successfully");

        trace!("Deleting supply and block reward");
        let supply: u64 = self.delete_cacheable_data(&self.supply, &None, &topoheight).await?;
        trace!("Supply was {}", supply);

        let reward: u64 = self.delete_cacheable_data(&self.rewards, &None, &topoheight).await?;
        trace!("Reward for block {} was: {}", hash, reward);

        trace!("Deleting difficulty");
        let _: Difficulty = self.delete_cacheable_data(&self.difficulty, &None, &hash).await?;

        trace!("Deleting cumulative difficulty");
        let cumulative_difficulty: CumulativeDifficulty = self.delete_cacheable_data(&self.cumulative_difficulty, &self.cumulative_difficulty_cache, &hash).await?;
        trace!("Cumulative difficulty deleted: {}", cumulative_difficulty);

        let mut txs = Vec::new();
        for tx_hash in block.get_transactions() {
            if self.has_tx_blocks(tx_hash)? {
                let mut blocks: Tips = self.delete_cacheable_data(&self.tx_blocks, &None, tx_hash).await?;
                let blocks_len =  blocks.len();
                blocks.remove(&hash);
                self.set_blocks_for_tx(tx_hash, &blocks)?;
                trace!("Tx was included in {}, blocks left: {}", blocks_len, blocks.into_iter().map(|b| b.to_string()).collect::<Vec<String>>().join(", "));
            }

            if self.is_tx_executed_in_a_block(tx_hash)? {
                trace!("Tx {} was executed, deleting", tx_hash);
                self.remove_tx_executed(&tx_hash)?;
            }

            // We have to check first as we may have already deleted it because of client protocol
            // which allow multiple time the same txs in differents blocks
            if self.contains_data(&self.transactions, &self.transactions_cache, tx_hash).await? {
                trace!("Deleting TX {} in block {}", tx_hash, hash);
                let tx: Arc<Transaction> = self.delete_data(&self.transactions, &self.transactions_cache, tx_hash).await?;
                txs.push((tx_hash.clone(), tx));
            }
        }

        // remove the block hash from the set, and delete the set if empty
        if self.has_blocks_at_height(block.get_height()).await? {
            self.remove_block_hash_at_height(&hash, block.get_height()).await?;
        }

        // Delete cache of past blocks
        if let Some(cache) = &self.past_blocks_cache {
            let mut cache = cache.lock().await;
            cache.pop(&hash);
        }

        Ok((hash, block, txs))
    }

    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned balances at topoheight {}", topoheight);
        for el in self.versioned_balances.scan_prefix(&topoheight.to_be_bytes()) {
            let (key, value) = el?;
            // Delete this version from DB
            self.versioned_balances.remove(&key)?;

            // Deserialize keys part
            let asset = Hash::from_bytes(&key[40..72])?;
            let key = PublicKey::from_bytes(&key[8..40])?;

            let last_topoheight = self.get_last_topoheight_for_balance(&key, &asset).await?;
            if last_topoheight >= topoheight {
                // Deserialize value, it is needed to get the previous topoheight
                let versioned_balance = VersionedBalance::from_bytes(&value)?;
    
                // Now records changes, for each balances
                let db_key = self.get_balance_key_for(&key, &asset);
                if let Some(previous_topoheight) = versioned_balance.get_previous_topoheight() {
                    self.balances.insert(&db_key, &previous_topoheight.to_be_bytes())?;
                } else {
                    // if there is no previous topoheight, it means that this is the first version
                    // so we can delete the balance
                    self.balances.remove(&db_key)?;
                }
            }
        }

        Ok(())
    }

    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces at topoheight {}", topoheight);
        for el in self.versioned_nonces.scan_prefix(&topoheight.to_be_bytes()) {
            let (key, value) = el?;
            // Delete this version from DB
            self.versioned_nonces.remove(&key)?;

            // Deserialize keys part
            let key = PublicKey::from_bytes(&key[8..40])?;

            // Because of chain reorg, it may have been already deleted
            if let Ok(last_topoheight) = self.get_last_topoheight_for_nonce(&key).await {
                if last_topoheight >= topoheight {
                    // Deserialize value, it is needed to get the previous topoheight
                    let version = VersionedNonce::from_bytes(&value)?;
                    // Now records changes
                    if let Some(previous_topoheight) = version.get_previous_topoheight() {
                        self.set_last_topoheight_for_nonce(&key, previous_topoheight).await?;
                    } else {
                        // if there is no previous topoheight, it means that this is the first version
                        // so we can delete the balance
                        self.delete_last_topoheight_for_nonce(&key).await?;
                    }
                }
            }
        }

        trace!("delete versioned nonces at topoheight {} done!", topoheight);
        Ok(())
    }

    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned balances above topoheight {}!", topoheight);
        self.delete_versioned_tree_above_topoheight(&self.versioned_balances, topoheight)
    }

    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces above topoheight {}", topoheight);
        self.delete_versioned_tree_above_topoheight(&self.versioned_nonces, topoheight)
    }

    async fn delete_registrations_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete registrations above topoheight {}", topoheight);
        for el in self.registrations_prefixed.iter().keys() {
            let key = el?;
            let topo = u64::from_bytes(&key[0..8])?;
            if topo > topoheight {
                self.registrations_prefixed.remove(&key)?;
                let pkey = &key[8..40];
                self.registrations.remove(&pkey)?;
            }
        }

        Ok(())
    }

    async fn delete_registrations_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete registrations below topoheight {}", topoheight);
        let mut buf = [0u8; 40];
        for el in self.registrations.iter() {
            let (key, value) = el?;
            let topo = u64::from_bytes(&value[0..8])?;
            if topo < topoheight {
                buf[0..8].copy_from_slice(&value);
                buf[8..40].copy_from_slice(&key);

                self.registrations_prefixed.remove(&buf)?;
                self.registrations.remove(&key)?;
            }
        }

        Ok(())
    }

    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned balances below topoheight {}!", topoheight);
        self.delete_versioned_tree_below_topoheight(&self.versioned_balances, topoheight)
    }

    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("delete versioned nonces below topoheight {}", topoheight);
        self.delete_versioned_tree_below_topoheight(&self.versioned_nonces, topoheight)
    }

    async fn create_snapshot_balances_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        // asset tree where PublicKey are stored with the highest balance topoheight in it
        for el in self.balances.iter() {
            let (key_bytes, value) = el?;
            let key = PublicKey::from_bytes(&key_bytes[0..32])?;
            let asset = Hash::from_bytes(&key_bytes[32..64])?;
            let highest_balance_topoheight = u64::from_bytes(&value)?;

            // retrieve the highest versioned balance
            let mut versioned_balance = self.get_balance_at_exact_topoheight(&key, &asset, highest_balance_topoheight).await?;

            // if the highest topoheight for this account is less than the snapshot topoheight
            // update it to the topoheight
            // otherwise, delete the previous topoheight in VersionedBalance which is under topoheight
            if highest_balance_topoheight < topoheight {
                // save the new highest topoheight
                self.balances.insert(&key_bytes, &topoheight.to_be_bytes())?;
                // remove the previous topoheight
                versioned_balance.set_previous_topoheight(None);

                // save it
                let key = self.get_versioned_balance_key(&key, &asset, topoheight);
                self.versioned_balances.insert(key, versioned_balance.to_bytes())?;
            } else {
                // find the first VersionedBalance which is under topoheight
                while let Some(previous_topoheight) = versioned_balance.get_previous_topoheight() {
                    if previous_topoheight < topoheight {
                        versioned_balance.set_previous_topoheight(None);
                        // save it
                        let key = self.get_versioned_balance_key(&key, &asset, topoheight);
                        self.versioned_balances.insert(key, versioned_balance.to_bytes())?;
                        break;
                    }

                    // keep searching
                    versioned_balance = self.get_balance_at_exact_topoheight(&key, &asset, previous_topoheight).await?;
                }
            }
        }

        Ok(())
    }

    async fn create_snapshot_nonces_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        // tree where VersionedNonce are stored
        // tree where PublicKey are stored with the highest noce topoheight in it
        for el in self.nonces.iter() {
            let (key_bytes, value) = el?;
            let key = PublicKey::from_bytes(&key_bytes)?;
            let highest_topoheight = u64::from_bytes(&value)?;

            // retrieve the highest versioned nonce
            let mut versioned_nonce = self.get_nonce_at_exact_topoheight(&key, highest_topoheight).await?;

            // if the highest topoheight for this account is less than the snapshot topoheight
            // update it to the topoheight
            // otherwise, delete the previous topoheight in VersionedNonce which is under topoheight
            if highest_topoheight < topoheight {
                // save the new highest topoheight
                self.nonces.insert(&key_bytes, &topoheight.to_be_bytes())?;
                // remove the previous topoheight
                versioned_nonce.set_previous_topoheight(None);

                // save it
                let key = self.get_versioned_nonce_key(&key, topoheight);
                self.versioned_nonces.insert(key, versioned_nonce.to_bytes())?;
            } else {
                // find the first VersionedBalance which is under topoheight
                while let Some(previous_topoheight) = versioned_nonce.get_previous_topoheight() {
                    if previous_topoheight < topoheight {
                        versioned_nonce.set_previous_topoheight(None);
                        // save it
                        let key = self.get_versioned_nonce_key(&key, topoheight);
                        self.versioned_nonces.insert(key, versioned_nonce.to_bytes())?;
                        break;
                    }

                    // keep searching
                    versioned_nonce = self.get_nonce_at_exact_topoheight(&key, previous_topoheight).await?;
                }
            }
        }

        Ok(())
    }

    async fn create_snapshot_registrations_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        // tree where PublicKey are stored with the registration topoheight in it
        let mut buf = [0u8; 40];
        for el in self.registrations.iter() {
            let (key, value) = el?;
            let registration_topo = u64::from_bytes(&value)?;

            // if the registration topoheight for this account is less than the snapshot topoheight
            // update it to the topoheight
            if registration_topo < topoheight {
                // Delete the prefixed registration
                buf[0..8].copy_from_slice(&value);
                buf[8..40].copy_from_slice(&key);
                self.registrations_prefixed.remove(&buf)?;

                // save the new registration topoheight
                self.registrations.insert(&key, &topoheight.to_be_bytes())?;
                self.registrations_prefixed.insert(&buf, &[])?;
            }
        }

        Ok(())
    }

    fn get_network(&self) -> Result<Network, BlockchainError> {
        trace!("get network");
        self.load_from_disk(&self.extra, NETWORK)
    }

    fn set_network(&mut self, network: &Network) -> Result<(), BlockchainError> {
        trace!("set network to {}", network);
        self.extra.insert(NETWORK, network.to_bytes())?;
        Ok(())
    }

    fn has_network(&self) -> Result<bool, BlockchainError> {
        trace!("has network");
        Ok(self.extra.contains_key(NETWORK)?)
    }

    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: u64, count: u64, stable_topo_height: u64) -> Result<(u64, u64, Vec<(Hash, Arc<Transaction>)>), BlockchainError> {
        trace!("pop blocks from height: {}, topoheight: {}, count: {}", height, topoheight, count);
        if topoheight < count as u64 { // also prevent removing genesis block
            return Err(BlockchainError::NotEnoughBlocks);
        }

        // search the lowest topo height available based on count + 1
        // (last lowest topo height accepted)
        let mut lowest_topo = topoheight - count;
        trace!("Lowest topoheight for rewind: {}", lowest_topo);

        let pruned_topoheight = self.get_pruned_topoheight().await?.unwrap_or(0);
        if pruned_topoheight != 0 {
            let safety_pruned_topoheight = pruned_topoheight + PRUNE_SAFETY_LIMIT;
            if lowest_topo <= safety_pruned_topoheight && stable_topo_height != 0 {
                warn!("Pruned topoheight is {}, lowest topoheight is {}, rewind only until {}", pruned_topoheight, lowest_topo, safety_pruned_topoheight);
                lowest_topo = safety_pruned_topoheight;
            }
        }

        // new TIPS for chain
        let mut tips = self.get_tips().await?;

        // Delete all orphaned blocks tips
        for tip in tips.clone() {
            if !self.is_block_topological_ordered(&tip).await {
                debug!("Tip {} is not ordered, removing", tip);
                tips.remove(&tip);
            }
        }

        // all txs to be rewinded
        let mut txs = Vec::new();
        let mut done = 0;
        'main: loop {
            // stop rewinding if its genesis block or if we reached the lowest topo
            if topoheight <= lowest_topo || topoheight <= stable_topo_height || height == 0 { // prevent removing genesis block
                trace!("Done: {done}, count: {count}, height: {height}, topoheight: {topoheight}, lowest topo: {lowest_topo}, stable topo: {stable_topo_height}");
                break 'main;
            }

            // Delete the hash at topoheight
            let (hash, block, block_txs) = self.delete_block_at_topoheight(topoheight).await?;
            txs.extend(block_txs);

            // generate new tips
            trace!("Removing {} from {} tips", hash, tips.len());
            tips.remove(&hash);
 
            for hash in block.get_tips() {
                trace!("Adding {} to {} tips", hash, tips.len());
                tips.insert(hash.clone());
            }

            if topoheight <= pruned_topoheight {
                warn!("Pruned topoheight is reached, this is not healthy, starting from 0");
                topoheight = 0;
                height = 0;

                tips.clear();
                tips.insert(self.get_hash_at_topo_height(0).await?);

                self.extra.remove(PRUNED_TOPOHEIGHT)?;
                self.pruned_topoheight = None;

                break 'main;
            }

            topoheight -= 1;
            // height of old block become new height
            if block.get_height() < height {
                height = block.get_height();
            }
            done += 1;
        }

        debug!("Blocks processed {}, new topoheight: {}, new height: {}, tips: {}", done, topoheight, height, tips.len());

        trace!("Cleaning assets");

        // All deleted assets
        let mut deleted_assets = HashSet::new();
        
        // clean all assets
        for el in self.assets.iter() {
            let (key, value) = el.context("error on asset iterator")?;
            let asset = Hash::from_bytes(&key)?;
            trace!("verifying asset registered: {}", asset);

            let registration_topoheight = u64::from_bytes(&value)?;
            if registration_topoheight > topoheight {
                trace!("Asset {} was registered at topoheight {}, deleting", asset, registration_topoheight);
                // Delete it from registered assets
                self.assets.remove(&key).context(format!("Error while deleting asset {asset} from registered assets"))?;

                // drop the tree for this asset
                self.db.drop_tree(key).context(format!("error on dropping asset {asset} tree"))?;

                deleted_assets.insert(asset);
            }
        }

        trace!("Cleaning nonces");
        // now let's process nonces versions
        // we set the new highest topoheight to the highest found under the new topoheight
        for el in self.nonces.iter() {
            let (key, value) = el?;
            let highest_topoheight = u64::from_bytes(&value)?;
            if highest_topoheight < pruned_topoheight {
                warn!("wrong nonce topoheight stored, highest topoheight is {}, pruned topoheight is {}", highest_topoheight, pruned_topoheight);
                self.nonces.remove(key)?;
                continue;
            }

            if highest_topoheight > topoheight {
                if self.nonces.remove(&key)?.is_some() {
                    self.store_accounts_count(self.count_accounts().await? - 1)?;
                }

                // find the first version which is under topoheight
                let pkey = PublicKey::from_bytes(&key)?;
                let mut version = self.get_nonce_at_exact_topoheight(&pkey, highest_topoheight).await
                    .context(format!("Error while retrieving nonce at exact topoheight {highest_topoheight}"))?;

                while let Some(previous_topoheight) = version.get_previous_topoheight() {
                    if previous_topoheight < topoheight {
                        // we find the new highest version which is under new topoheight
                        trace!("New highest version nonce for {} is at topoheight {}", pkey.as_address(self.is_mainnet()), previous_topoheight);
                        if self.nonces.insert(&key, &previous_topoheight.to_be_bytes())?.is_none() {
                            self.store_accounts_count(self.count_accounts().await? + 1)?;
                        }
                        break;
                    }

                    // keep searching
                    version = self.get_nonce_at_exact_topoheight(&pkey, previous_topoheight).await
                        .context(format!("Error while searching nonce at exact topoheight"))?;
                }
            } else {
                // nothing to do as its under the rewinded topoheight
            }
        }

        trace!("Cleaning balances");
        // do balances too
        for el in self.balances.iter() {
            let (key, value) = el?;
            let asset = Hash::from_bytes(&key[32..64])?;
            let mut delete = true;

            
            // if the asset is not deleted, we can process it
            if !deleted_assets.contains(&asset) {
                let highest_topoheight = u64::from_bytes(&value)?;
                if highest_topoheight > topoheight && highest_topoheight >= pruned_topoheight {
                    // find the first version which is under topoheight
                    let pkey = PublicKey::from_bytes(&key[0..32])?;

                    let mut version = self.get_balance_at_exact_topoheight(&pkey, &asset, highest_topoheight).await
                    .context(format!("Error while retrieving balance at exact topoheight {highest_topoheight}"))?;

                    while let Some(previous_topoheight) = version.get_previous_topoheight() {
                        if previous_topoheight < topoheight {
                            // we find the new highest version which is under new topoheight
                            trace!("New highest version balance for {} is at topoheight {} with asset {}", pkey.as_address(self.is_mainnet()), previous_topoheight, asset);
                            self.balances.insert(&key, &previous_topoheight.to_be_bytes())?;
                            delete = false;
                            break;
                        }
    
                        // keep searching
                        version = self.get_balance_at_exact_topoheight(&pkey, &asset, previous_topoheight).await?;
                    }
                }
            }

            if delete {
                self.balances.remove(&key)?;
            }
        }

        warn!("Blocks rewinded: {}, new topoheight: {}, new height: {}", done, topoheight, height);

        trace!("Cleaning versioned balances and nonces");

        // now delete all versioned balances and nonces above the new topoheight
        self.delete_versioned_balances_above_topoheight(topoheight).await?;
        self.delete_versioned_nonces_above_topoheight(topoheight).await?;
        // Delete also registrations
        self.delete_registrations_above_topoheight(topoheight).await?;

        trace!("Cleaning caches");
        // Clear all caches to not have old data after rewind
        self.clear_caches().await?;

        trace!("Storing new pointers");
        // store the new tips and topo topoheight
        self.store_tips(&tips)?;
        self.set_top_topoheight(topoheight)?;
        self.set_top_height(height)?;

        // Reduce the count of blocks stored
        let count = self.count_blocks().await? - done;
        self.extra.insert(BLOCKS_COUNT, &count.to_be_bytes())?;

        Ok((height, topoheight, txs))
    }

    async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        trace!("get top block hash");
        self.get_hash_at_topo_height(self.get_top_topoheight()?).await
    }

    fn get_top_topoheight(&self) -> Result<u64, BlockchainError> {
        trace!("get top topoheight");
        self.load_from_disk(&self.extra, TOP_TOPO_HEIGHT)
    }

    fn set_top_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("set new top topoheight at {}", topoheight);
        self.extra.insert(TOP_TOPO_HEIGHT, &topoheight.to_be_bytes())?;
        Ok(())
    }

    fn get_top_height(&self) -> Result<u64, BlockchainError> {
        trace!("get top height");
        self.load_from_disk(&self.extra, TOP_HEIGHT)
    }

    fn set_top_height(&mut self, height: u64) -> Result<(), BlockchainError> {
        trace!("set new top height at {}", height);
        self.extra.insert(TOP_HEIGHT, &height.to_be_bytes())?;
        Ok(())
    }

    async fn get_top_block_header(&self) -> Result<(Arc<BlockHeader>, Hash), BlockchainError> {
        trace!("get top block header");
        let hash = self.get_top_block_hash().await?;
        Ok((self.get_block_header_by_hash(&hash).await?, hash))
    }

    async fn get_top_block(&self) -> Result<Block, BlockchainError> {
        trace!("get top block");
        let (block, _) = self.get_top_block_header().await?;
        let mut transactions = Vec::new();
        for tx in block.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let block = Block::new(Immutable::Arc(block), transactions);
        Ok(block)
    }

    async fn get_tips(&self) -> Result<Tips, BlockchainError> {
        trace!("get tips");
        Ok(self.tips_cache.clone())
    }

    fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError> {
        trace!("Saving {} Tips", tips.len());
        self.extra.insert(TIPS, tips.to_bytes())?;
        self.tips_cache = tips.clone();
        Ok(())
    }

    // Returns the current size on disk in bytes
    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError> {
        Ok(self.db.size_on_disk()?)
    }

    async fn stop(&mut self) -> Result<(), BlockchainError> {
        info!("Flushing Sled database");
        self.db.flush_async().await?;
        info!("Sled database flushed");
        Ok(())
    }
}