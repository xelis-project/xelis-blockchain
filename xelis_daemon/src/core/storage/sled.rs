use async_trait::async_trait;
use indexmap::IndexSet;
use crate::core::error::{BlockchainError, DiskContext};
use xelis_common::{
    serializer::{Reader, Serializer},
    crypto::{key::PublicKey, hash::{Hash, hash}},
    immutable::Immutable,
    transaction::Transaction,
    block::{BlockHeader, Block, Difficulty},
    account::{VersionedBalance, VersionedNonce},
    network::Network, asset::{AssetData, AssetWithData},
};
use std::{
    collections::HashSet,
    hash::Hash as StdHash,
    sync::Arc
};
use tokio::sync::Mutex;
use lru::LruCache;
use sled::Tree;
use log::{debug, trace, error, warn};

use super::{Tips, Storage, DifficultyProvider};

const TIPS: &[u8; 4] = b"TIPS";
const TOP_TOPO_HEIGHT: &[u8; 4] = b"TOPO";
const TOP_HEIGHT: &[u8; 4] = b"TOPH";
const NETWORK: &[u8] = b"NET";
const PRUNED_TOPOHEIGHT: &[u8; 4] = b"PRUN";
const NONCE_PREFIX: &[u8; 4] = b"NONC";

pub struct SledStorage {
    transactions: Tree, // all txs stored on disk
    txs_executed: Tree, // all txs executed in block
    blocks: Tree, // all blocks on disk
    blocks_at_height: Tree, // all blocks height at specific height
    extra: Tree, // all extra data saved on disk
    topo_by_hash: Tree, // topo at hash on disk
    hash_at_topo: Tree, // hash at topo height on disk
    cumulative_difficulty: Tree, // cumulative difficulty for each block hash on disk
    assets: Tree, // keep tracks of all available assets on network
    nonces: Tree, // account nonces to prevent TX replay attack
    rewards: Tree, // block reward for each block topoheight
    supply: Tree, // supply for each block topoheight
    difficulty: Tree, // difficulty for each block hash
    tx_blocks: Tree, // tree to store all blocks hashes where a tx was included in 
    db: sled::Db, // opened DB used for assets to create dynamic assets
    // cached in memory
    transactions_cache: Option<Mutex<LruCache<Hash, Arc<Transaction>>>>,
    blocks_cache: Option<Mutex<LruCache<Hash, Arc<BlockHeader>>>>,
    past_blocks_cache: Option<Mutex<LruCache<Hash, Arc<Vec<Hash>>>>>, // previous blocks saved at each new block
    topo_by_hash_cache: Option<Mutex<LruCache<Hash, u64>>>,
    hash_at_topo_cache: Option<Mutex<LruCache<u64, Hash>>>,
    cumulative_difficulty_cache: Option<Mutex<LruCache<Hash, Difficulty>>>,
    assets_cache: Option<Mutex<LruCache<Hash, ()>>>,
    balances_trees_cache: Option<Mutex<LruCache<(Hash, u64), Tree>>>, // versioned balances tree keep in cache to prevent hash recompute
    nonces_trees_cache: Option<Mutex<LruCache<u64, Tree>>>, // versioned nonces tree keep in cache to prevent hash recompute
    tips_cache: Tips,
    pruned_topoheight: Option<u64>
}

macro_rules! init_cache {
    ($cache_size: expr) => {{
        if let Some(size) = &$cache_size {
            Some(Mutex::new(LruCache::new(*size)))
        } else {
            None
        }
    }};
}

impl SledStorage {
    pub fn new(dir_path: String, cache_size: Option<usize>, network: Network) -> Result<Self, BlockchainError> {
        let sled = sled::open(dir_path)?;
        let mut storage = Self {
            transactions: sled.open_tree("transactions")?,
            txs_executed: sled.open_tree("txs_executed")?,
            blocks: sled.open_tree("blocks")?,
            blocks_at_height: sled.open_tree("blocks_at_height")?,
            extra: sled.open_tree("extra")?,
            topo_by_hash: sled.open_tree("topo_at_hash")?,
            hash_at_topo: sled.open_tree("hash_at_topo")?,
            cumulative_difficulty: sled.open_tree("cumulative_difficulty")?,
            assets: sled.open_tree("assets")?,
            nonces: sled.open_tree("nonces")?,
            rewards: sled.open_tree("rewards")?,
            supply: sled.open_tree("supply")?,
            difficulty: sled.open_tree("difficulty")?,
            tx_blocks: sled.open_tree("tx_blocks")?,
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
            pruned_topoheight: None
        };

        if storage.has_network()? {
            let storage_network = storage.get_network()?;
            if storage_network != network {
                return Err(BlockchainError::InvalidNetwork);
            }
        } else {
            storage.set_network(&network)?;
        }

        if let Ok(tips) = storage.load_from_disk::<Tips>(&storage.extra, TIPS) {
            debug!("Found tips: {}", tips.len());
            storage.tips_cache = tips;
        }

        if let Ok(pruned_topoheight) = storage.load_from_disk::<u64>(&storage.extra, PRUNED_TOPOHEIGHT) {
            debug!("Found pruned topoheight: {}", pruned_topoheight);
            storage.pruned_topoheight = Some(pruned_topoheight);
        }

        Ok(storage)
    }

    async fn clear_caches(&self) {
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
    }

    fn load_from_disk<T: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<T, BlockchainError> {
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

    async fn get_cacheable_arc_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, Arc<V>>>>, key: &K) -> Result<Arc<V>, BlockchainError> {
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

    async fn get_cacheable_data_copiable<K: Eq + StdHash + Serializer + Clone, V: Serializer + Copy>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<V, BlockchainError> {
        let value = if let Some(cache) = cache {
            let mut cache = cache.lock().await;
            if let Some(value) = cache.get(key) {
                return Ok(*value);
            }

            let value = self.load_from_disk(tree, &key.to_bytes())?;
            cache.put(key.clone(), value);
            value
        } else {
            self.load_from_disk(tree, &key.to_bytes())?
        };

        Ok(value)
    }

    async fn delete_cacheable_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<V, BlockchainError> {
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

    async fn delete_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, Arc<V>>>>, key: &K) -> Result<Arc<V>, BlockchainError> {
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

    async fn contains_data<K: Eq + StdHash + Serializer + Clone, V>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<bool, BlockchainError> {
        if let Some(cache) = cache {
            let cache = cache.lock().await;
            return Ok(cache.contains(key) || tree.contains_key(&key.to_bytes())?)
        }

        Ok(tree.contains_key(&key.to_bytes())?)
    }

    // hash asset + topoheight to create a unique key
    fn generate_versioned_balance_key(&self, asset: &Hash, topoheight: u64) -> Result<Hash, BlockchainError> {
        trace!("generate versioned balance key for {} at {}", asset, topoheight);
        let mut bytes = asset.to_bytes();
        bytes.extend_from_slice(&topoheight.to_be_bytes());
        let key = hash(&bytes);
        Ok(key)
    }

    // returns the Tree from cache or insert it and returns it
    // if no cache, compute the key each time this function is called.
    async fn get_versioned_balance_tree(&self, asset: &Hash, topoheight: u64) -> Result<Tree, BlockchainError> {
        trace!("get versioned balance tree for {} at {}", asset, topoheight);
        let tree = if let Some(cache) = &self.balances_trees_cache {
            let mut balances = cache.lock().await;
            let cache_key = (asset.clone(), topoheight);
            if let Some(tree) = balances.get(&cache_key) {
                tree.clone()
            } else { // not found in cache, compute it and insert it
                let key = self.generate_versioned_balance_key(asset, topoheight)?;
                let tree = self.db.open_tree(key.as_bytes())?;
                balances.put(cache_key, tree.clone());
                tree
            }
        } else { // no cache found, we have to compute it ourself
            let key = self.generate_versioned_balance_key(asset, topoheight)?;
            self.db.open_tree(key.as_bytes())?
        };

        Ok(tree)
    }

    // constant prefix + topoheight to create a unique key
    fn generate_versioned_nonce_key(&self, topoheight: u64) -> Result<[u8; 12], BlockchainError> {
        trace!("generate versioned nonce key at {}", topoheight);
        let mut bytes = [0u8; 12]; // 4 bytes for prefix, 8 for u64
        bytes[0..4].copy_from_slice(NONCE_PREFIX);
        bytes[4..12].copy_from_slice(&topoheight.to_be_bytes());
        Ok(bytes)
    }

    // returns the Tree from cache or insert it and returns it
    // if no cache, compute the key each time this function is called.
    async fn get_versioned_nonce_tree(&self, topoheight: u64) -> Result<Tree, BlockchainError> {
        trace!("get versioned nonce tree at {}", topoheight);
        let tree = if let Some(cache) = &self.nonces_trees_cache {
            let mut nonces = cache.lock().await;
            if let Some(tree) = nonces.get(&topoheight) {
                tree.clone()
            } else { // not found in cache, compute it and insert it
                let key = self.generate_versioned_nonce_key(topoheight)?;
                let tree = self.db.open_tree(key)?;
                nonces.put(topoheight, tree.clone());
                tree
            }
        } else { // no cache found, we have to compute it ourself
            let key = self.generate_versioned_nonce_key(topoheight)?;
            self.db.open_tree(key)?
        };

        Ok(tree)
    }
}


#[async_trait]
impl DifficultyProvider for SledStorage {
    // TODO optimize all these functions to read only what is necessary
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        trace!("get height for block hash {}", hash);
        let block = self.get_block_header_by_hash(hash).await?;
        Ok(block.get_height())
    }

    async fn get_timestamp_for_block_hash(&self, hash: &Hash) -> Result<u128, BlockchainError> {
        trace!("get timestamp for hash {}", hash);
        let block = self.get_block_header_by_hash(hash).await?;
        Ok(block.get_timestamp())
    }

    async fn get_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError> {
        trace!("get difficulty for hash {}", hash);
        self.load_from_disk(&self.difficulty, hash.as_bytes())
    }

    async fn get_cumulative_difficulty_for_block_hash(&self, hash: &Hash) -> Result<Difficulty, BlockchainError> {
        trace!("get cumulative difficulty for hash {}", hash);
        self.get_cacheable_data_copiable(&self.cumulative_difficulty, &self.cumulative_difficulty_cache, hash).await
    }

    async fn get_past_blocks_for_block_hash(&self, hash: &Hash) -> Result<Arc<Vec<Hash>>, BlockchainError> {
        trace!("get past blocks of {}", hash);
        let tips = if let Some(cache) = &self.past_blocks_cache {
            let mut cache = cache.lock().await;
            if let Some(tips) = cache.get(hash) {
                return Ok(tips.clone())
            }
    
            let block = self.get_block_header_by_hash(hash).await?;
            let mut tips = Vec::with_capacity(block.get_tips().len());
            for hash in block.get_tips() {
                tips.push(hash.clone());
            }
    
            let tips = Arc::new(tips);
            cache.put(hash.clone(), tips.clone());
            tips
        } else {
            let block = self.get_block_header_by_hash(hash).await?;
            let mut tips = Vec::with_capacity(block.get_tips().len());
            for hash in block.get_tips() {
                tips.push(hash.clone());
            }
            Arc::new(tips)
        };

        Ok(tips)
    }

    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Arc<BlockHeader>, BlockchainError> {
        trace!("get block by hash: {}", hash);
        self.get_cacheable_arc_data(&self.blocks, &self.blocks_cache, hash).await
    }
}

#[async_trait]
impl Storage for SledStorage {
    fn get_pruned_topoheight(&self) -> Result<Option<u64>, BlockchainError> {
        Ok(self.pruned_topoheight)
    }

    fn set_pruned_topoheight(&mut self, pruned_topoheight: u64) -> Result<(), BlockchainError> {
        self.pruned_topoheight = Some(pruned_topoheight);
        self.extra.insert(PRUNED_TOPOHEIGHT, &pruned_topoheight.to_be_bytes())?;
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
        let cumulative_difficulty: Difficulty = self.delete_cacheable_data(&self.cumulative_difficulty, &self.cumulative_difficulty_cache, &hash).await?;
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

    async fn delete_tx(&mut self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        self.delete_cacheable_data::<Hash, HashSet<Hash>>(&self.tx_blocks, &None, hash).await?;
        self.delete_data(&self.transactions, &self.transactions_cache, hash).await
    }

    async fn delete_versioned_balances_for_asset_at_topoheight(&mut self, asset: &Hash, topoheight: u64) -> Result<(), BlockchainError> {
        let tree = self.get_versioned_balance_tree(asset, topoheight).await?;
        self.db.drop_tree(tree.name())?;
        Ok(())
    }

    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        let tree = self.get_versioned_nonce_tree(topoheight).await?;
        self.db.drop_tree(tree.name())?;
        Ok(())
    }

    async fn create_snapshot_balances_at_topoheight(&mut self, assets: &Vec<Hash>, topoheight: u64) -> Result<(), BlockchainError> {
        for asset in assets {
            // tree where VersionedBalance are stored
            let versioned_tree = self.get_versioned_balance_tree(asset, topoheight).await?;
            // asset tree where PublicKey are stored with the highest balance topoheight in it
            let tree = self.db.open_tree(asset.as_bytes())?;
            for el in tree.iter() {
                let (key_bytes, value) = el?;
                let key = PublicKey::from_bytes(&key_bytes)?;
                let highest_balance_topoheight = u64::from_bytes(&value)?;

                // retrieve the highest versioned balance
                let mut versioned_balance = self.get_balance_at_exact_topoheight(&key, asset, highest_balance_topoheight).await?;

                // if the highest topoheight for this account is less than the snapshot topoheight
                // update it to the topoheight
                // otherwise, delete the previous topoheight in VersionedBalance which is under topoheight
                if highest_balance_topoheight < topoheight {
                    // save the new highest topoheight
                    tree.insert(&key_bytes, &topoheight.to_be_bytes())?;
                    // remove the previous topoheight
                    versioned_balance.set_previous_topoheight(None);

                    // save it
                    versioned_tree.insert(key_bytes, versioned_balance.to_bytes())?;
                } else {
                    // find the first VersionedBalance which is under topoheight
                    while let Some(previous_topoheight) = versioned_balance.get_previous_topoheight() {
                        if previous_topoheight < topoheight {
                            versioned_balance.set_previous_topoheight(None);
                            // save it
                            versioned_tree.insert(key_bytes, versioned_balance.to_bytes())?;
                            break;
                        }

                        // keep searching
                        versioned_balance = self.get_balance_at_exact_topoheight(&key, asset, previous_topoheight).await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn create_snapshot_nonces_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError> {
        // tree where VersionedNonce are stored
        let versioned_tree = self.get_versioned_nonce_tree(topoheight).await?;
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
                versioned_tree.insert(key_bytes, versioned_nonce.to_bytes())?;
            } else {
                // find the first VersionedBalance which is under topoheight
                while let Some(previous_topoheight) = versioned_nonce.get_previous_topoheight() {
                    if previous_topoheight < topoheight {
                        versioned_nonce.set_previous_topoheight(None);
                        // save it
                        versioned_tree.insert(key_bytes, versioned_nonce.to_bytes())?;
                        break;
                    }

                    // keep searching
                    versioned_nonce = self.get_nonce_at_exact_topoheight(&key, previous_topoheight).await?;
                }
            }
        }

        Ok(())
    }

    async fn get_partial_assets(&self, maximum: usize, skip: usize, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<IndexSet<AssetWithData>, BlockchainError> {
        let mut assets = IndexSet::new();
        let mut skip_count = 0;
        for el in self.assets.iter() {
            let (key, value) = el?;
            let data = AssetData::from_bytes(&value)?;
            // check that we have a registered asset before the maximum topoheight
            if data.get_topoheight() >= minimum_topoheight && data.get_topoheight() <= maximum_topoheight {
                if skip_count < skip {
                    skip_count += 1;
                } else {
                    let asset = Hash::from_bytes(&key)?;
                    assets.insert(AssetWithData::new(asset, data));

                    if assets.len() == maximum {
                        break;
                    }
                }
            }
        }
        Ok(assets)
    }

    // Get all keys that got a changes in their balances/nonces in the range given
    async fn get_partial_keys(&self, maximum: usize, skip: usize, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<IndexSet<PublicKey>, BlockchainError> {
        let mut keys: IndexSet<PublicKey> = IndexSet::new();
        let mut skip_count = 0;
        for el in self.nonces.iter().keys() {
            let key = el?;
            let pkey = PublicKey::from_bytes(&key)?;

            // check that we have a nonce before the maximum topoheight
            if self.has_key_updated_in_range(&pkey, minimum_topoheight, maximum_topoheight).await? {
                if skip_count < skip {
                    skip_count += 1;
                } else {
                    keys.insert(pkey);

                    if keys.len() == maximum {
                        break;
                    }
                }
            }
        }

        Ok(keys)
    }

    async fn has_key_updated_in_range(&self, key: &PublicKey, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<bool, BlockchainError> {
        trace!("has key {} updated in range min topoheight {} and max topoheight {}", key, minimum_topoheight, maximum_topoheight);
        // check first that this address has nonce, if no returns None
        if !self.has_nonce(key).await? {
            return Ok(false)
        }

        // fast path check the latest nonce
        let (topo, mut version) = self.get_last_nonce(key).await?;
        trace!("Last version of nonce for {} is at topoheight {}", key, topo);
        
        // TODO Should we keep it ? We have to checks incoming txs too!
        // if its last nonce is under minimum topoheight, we can stop
        // if topo < minimum_topoheight {
        //     trace!("Last version nonce (invalid) found at {} (minimum topoheight = {})", topo, minimum_topoheight);
        //     return Ok(false)
        // }

        // if it's the latest and its under the maximum topoheight and above minimum topoheight
        if topo >= minimum_topoheight && topo <= maximum_topoheight {
            trace!("Last version nonce (valid) found at {} (maximum topoheight = {})", topo, maximum_topoheight);
            return Ok(true)
        }

        // otherwise, we have to go through the whole chain
        while let Some(previous) = version.get_previous_topoheight() {
            // we are under the minimum topoheight, we can stop
            if previous < minimum_topoheight {
                break;
            }

            let previous_version = self.get_nonce_at_exact_topoheight(key, previous).await?;
            trace!("previous nonce version is at {}", previous);
            if previous <= maximum_topoheight {
                trace!("Highest version nonce found at {} (maximum topoheight = {})", previous, maximum_topoheight);
                return Ok(true)
            }

            // security in case of DB corruption
            if let Some(value) = previous_version.get_previous_topoheight() {
                if value > previous {
                    error!("FATAL ERROR: Previous topoheight ({}) should not be higher than current version ({})!", value, previous);
                    return Err(BlockchainError::Unknown)
                }
            }
            version = previous_version;
        }

        // if we are here, we didn't find any nonce in the range
        // it start to be more and more heavy...
        // lets check on balances now...

        // check that we have a VersionedBalance between range given
        for asset in self.get_assets_for(key).await? {
            let (topo, mut version) = self.get_last_balance(key, &asset).await?;
            if topo >= minimum_topoheight && topo <= maximum_topoheight {
                return Ok(true)
            }

            while let Some(previous) = version.get_previous_topoheight() {
                // we are under the minimum topoheight, we can stop
                if previous < minimum_topoheight {
                    break;
                }

                let previous_version = self.get_balance_at_exact_topoheight(key, &asset, previous).await?;
                if previous <= maximum_topoheight {
                    return Ok(true)
                }

                // security in case of DB corruption
                if let Some(value) = previous_version.get_previous_topoheight() {
                    if value > previous {
                        error!("FATAL ERROR: Previous topoheight for balance ({}) should not be higher than current version of balance ({})!", value, previous);
                        return Err(BlockchainError::Unknown)
                    }
                }
                version = previous_version;
            }
        }

        Ok(false)
    }

    async fn get_balances<'a, I: Iterator<Item = &'a PublicKey> + Send>(&self, asset: &Hash, keys: I, maximum_topoheight: u64) -> Result<Vec<Option<u64>>, BlockchainError> {
        let mut balances = Vec::new();
        for key in keys {
            if self.has_balance_for(key, asset).await? {
                let res = match self.get_balance_at_maximum_topoheight(key, asset, maximum_topoheight).await? {
                    Some((_, version)) => Some(version.get_balance()),
                    None => None
                };
                balances.push(res);
            } else {
                balances.push(None);
            }
        }
        Ok(balances)
    }

    fn count_accounts(&self) -> usize {
        self.nonces.len()
    }

    fn get_block_executer_for_tx(&self, tx: &Hash) -> Result<Hash, BlockchainError> {
        self.load_from_disk(&self.txs_executed, tx.as_bytes())
    }

    fn set_tx_executed_in_block(&mut self, tx: &Hash, block: &Hash) -> Result<(), BlockchainError> {
        self.txs_executed.insert(tx.as_bytes(), block.as_bytes())?;
        Ok(())
    }

    fn remove_tx_executed(&mut self, tx: &Hash) -> Result<(), BlockchainError> {
        self.txs_executed.remove(tx.as_bytes())?;
        Ok(())
    }

    fn is_tx_executed_in_a_block(&self, tx: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.txs_executed.contains_key(tx.as_bytes())?)
    }

    fn is_tx_executed_in_block(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        if let Ok(hash) = self.get_block_executer_for_tx(tx) {
            if hash == *block {
                return Ok(true)
            }
        }
        Ok(false)
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

    async fn asset_exist(&self, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("asset exist {}", asset);
        self.contains_data(&self.assets, &self.assets_cache, asset).await
    }

    async fn add_asset(&mut self, asset: &Hash, data: AssetData) -> Result<(), BlockchainError> {
        trace!("add asset {} at topoheight {}", asset, data.get_topoheight());
        self.assets.insert(asset.as_bytes(), data.to_bytes())?;
        if let Some(cache) = &self.assets_cache {
            let mut cache = cache.lock().await;
            cache.put(asset.clone(), ());
        }
        Ok(())
    }

    // we are forced to read from disk directly because cache may don't have all assets in memory
    async fn get_assets(&self) -> Result<Vec<Hash>, BlockchainError> {
        trace!("get assets");
        let mut assets = Vec::new();
        for e in self.assets.iter().keys() {
            let key = e?;
            let mut reader = Reader::new(&key);
            let hash = Hash::read(&mut reader)?;
            assets.push(hash);
        }

        Ok(assets)
    }

    // count assets in storage
    fn count_assets(&self) -> usize {
        self.assets.len()
    }

    fn get_asset_data(&self, asset: &Hash) -> Result<AssetData, BlockchainError> {
        trace!("get asset registration topoheight {}", asset);
        self.load_from_disk(&self.assets, asset.as_bytes())
    }

    fn has_tx_blocks(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has tx blocks {}", hash);
        let contains = self.tx_blocks.contains_key(hash.as_bytes())?;
        Ok(contains)
    }

    fn has_block_linked_to_tx(&self, tx: &Hash, block: &Hash) -> Result<bool, BlockchainError> {
        trace!("has block {} linked to tx {}", block, tx);
        Ok(self.has_tx_blocks(tx)? && self.get_blocks_for_tx(tx)?.contains(block))
    }

    fn get_blocks_for_tx(&self, hash: &Hash) -> Result<Tips, BlockchainError> {
        trace!("get blocks for tx {}", hash);
        self.load_from_disk(&self.tx_blocks, hash.as_bytes())
    }

    fn add_block_for_tx(&mut self, tx: &Hash, block: &Hash) -> Result<(), BlockchainError> {
        trace!("add block {} for tx {}", block, tx);
        let mut blocks = if self.has_tx_blocks(tx)? {
            self.get_blocks_for_tx(tx)?
        } else {
            Tips::new()
        };

        if !blocks.contains(&block) {
            blocks.insert(block.clone());
            self.set_blocks_for_tx(tx, &blocks)?;
        }

        Ok(())
    }

    fn set_blocks_for_tx(&mut self, tx: &Hash, blocks: &HashSet<Hash>) -> Result<(), BlockchainError> {
        trace!("set blocks ({}) for tx {} ", blocks.len(), tx);
        self.tx_blocks.insert(tx.as_bytes(), blocks.to_bytes())?;
        Ok(())
    }

    async fn has_balance_for(&self, key: &PublicKey, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("has balance {} for {}", asset, key);
        if !self.asset_exist(asset).await? {
            return Err(BlockchainError::AssetNotFound(asset.clone()))
        }

        let tree = self.db.open_tree(asset.as_bytes())?;
        Ok(tree.contains_key(key.as_bytes())?)
    }

    // Returns all balances that the key has
    async fn get_assets_for(&self, key: &PublicKey) -> Result<Vec<Hash>, BlockchainError> {
        let mut assets = Vec::new();
        for el in self.assets.iter().keys() {
            let bytes = el?;
            let tree = self.db.open_tree(&bytes)?;
            if tree.contains_key(key.as_bytes())? {
                let hash = Hash::from_bytes(&bytes)?;
                assets.push(hash);
            }
        }
        Ok(assets)
    }

    // returns the highest topoheight where a balance changes happened
    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<u64, BlockchainError> {
        trace!("get last topoheight for balance {} for {}", asset, key);
        if !self.has_balance_for(key, asset).await? {
            return Ok(0)
        }

        let tree = self.db.open_tree(asset.as_bytes())?;
        self.get_cacheable_data_copiable(&tree, &None, key).await
    }

    // set in storage the new top topoheight (the most up-to-date versioned balance)
    fn set_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("set last topoheight to {} for balance {} for {}", topoheight, asset, key);
        let tree = self.db.open_tree(asset.as_bytes())?;
        tree.insert(&key.as_bytes(), &topoheight.to_be_bytes())?;
        Ok(())
    }

    // get the balance at a specific topoheight
    // if there is no balance change at this topoheight just return an error
    async fn has_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<bool, BlockchainError> {
        trace!("has balance {} for {} at exact topoheight {}", asset, key, topoheight);
        // check first that this address has balance, if no returns
        if !self.has_balance_for(key, asset).await? {
            return Ok(false)
        }

        let tree = self.get_versioned_balance_tree(asset, topoheight).await?;
        self.contains_data::<PublicKey, ()>(&tree, &None, key).await
    }

    // get the balance at a specific topoheight
    // if there is no balance change at this topoheight just return an error
    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError> {
        trace!("get balance {} for {} at exact topoheight {}", asset, key, topoheight);
        // check first that this address has balance, if no returns
        if !self.has_balance_at_exact_topoheight(key, asset, topoheight).await? {
            return Err(BlockchainError::NoBalanceChanges(key.clone()))
        }

        let tree = self.get_versioned_balance_tree(asset, topoheight).await?;
        self.get_cacheable_data_copiable(&tree, &None, key).await.map_err(|_| BlockchainError::NoBalanceChanges(key.clone()))
    }

    // delete the last topoheight registered for this key
    // it can happens when rewinding chain and we don't have any changes (no transaction in/out) for this key
    // because all versioned balances got deleted
    fn delete_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash) -> Result<(), BlockchainError> {
        trace!("delete last topoheight balance {} for {}", asset, key);
        let tree = self.db.open_tree(asset.as_bytes())?;
        tree.remove(&key.as_bytes())?;
        Ok(())
    }

    // get the latest balance at maximum specified topoheight
    // when a DAG re-ordering happens, we need to select the right balance and not the last one
    // returns None if the key has no balances for this asset
    // Maximum topoheight is inclusive
    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<Option<(u64, VersionedBalance)>, BlockchainError> {
        trace!("get balance {} for {} at maximum topoheight {}", asset, key, topoheight);
        // check first that this address has balance for this asset, if no returns None
        if !self.has_balance_for(key, asset).await? {
            return Ok(None)
        }

        // Fast path: if the balance is at exact topoheight, return it
        if self.has_balance_at_exact_topoheight(key, asset, topoheight).await? {
            trace!("Balance version found at exact (maximum) topoheight {}", topoheight);
            return Ok(Some((topoheight, self.get_balance_at_exact_topoheight(key, asset, topoheight).await?)))
        }

        let (topo, mut version) = self.get_last_balance(key, asset).await?;
        trace!("Last version balance {} for {} is at topoheight {}", asset, key, topo);
        // if it's the latest and its under the maximum topoheight
        if topo <= topoheight {
            trace!("Last version balance (valid) found at {} (maximum topoheight = {})", topo, topoheight);
            return Ok(Some((topo, version)))
        }

        // otherwise, we have to go through the whole chain
        while let Some(previous) = version.get_previous_topoheight() {
            let previous_version = self.get_balance_at_exact_topoheight(key, asset, previous).await?;
            trace!("previous version {}", previous);
            if previous <= topoheight {
                trace!("Highest version balance found at {} (maximum topoheight = {})", topo, topoheight);
                return Ok(Some((previous, previous_version)))
            }

            if let Some(value) = previous_version.get_previous_topoheight() {
                if value > previous {
                    error!("FATAL ERROR: Previous topoheight ({}) should not be higher than current version ({})!", value, previous);
                    return Err(BlockchainError::Unknown)
                }
            }
            version = previous_version;
        }

        Ok(None)
    }

    // delete versioned balances for this topoheight
    async fn delete_balance_at_topoheight(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError> {
        trace!("delete balance {} for {} at topoheight {}", asset, key, topoheight);
        let tree = self.get_versioned_balance_tree(asset, topoheight).await?;
        self.delete_cacheable_data(&tree, &None, key).await.map_err(|_| BlockchainError::NoBalanceChanges(key.clone()))
    }

    // returns a new versioned balance with already-set previous topoheight
    async fn get_new_versioned_balance(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError> {
        trace!("get new versioned balance {} for {} at {}", asset, key, topoheight);
        let version = match self.get_balance_at_maximum_topoheight(key, asset, topoheight).await? {
            Some((topo, mut version)) => {
                trace!("new versioned balance (balance at maximum topoheight) topo: {}, previous: {:?}", topo, version.get_previous_topoheight());
                // if its not at exact topoheight, then we set it as "previous topoheight"
                if topo != topoheight {
                    trace!("topo {} != topoheight {}, set topo {} as previous topoheight", topo, topoheight, topo);
                    version.set_previous_topoheight(Some(topo));
                }
                version
            },
            None => VersionedBalance::new(0, None)
        };

        Ok(version)
    }

    // save a new versioned balance in storage and update the pointer
    async fn set_balance_to(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64, version: &VersionedBalance) -> Result<(), BlockchainError> {
        trace!("set balance {} for {} to topoheight {}", asset, key, topoheight);
        self.set_balance_at_topoheight(asset, topoheight, key, &version).await?;
        self.set_last_topoheight_for_balance(key, asset, topoheight)?;
        Ok(())
    }

    // get the last version of balance and returns topoheight
    async fn get_last_balance(&self, key: &PublicKey, asset: &Hash) -> Result<(u64, VersionedBalance), BlockchainError> {
        trace!("get last balance {} for {}", asset, key);
        if !self.has_balance_for(key, asset).await? {
            return Err(BlockchainError::NoBalance(key.clone()))
        }

        let tree = self.db.open_tree(asset.as_bytes())?;
        let topoheight = self.get_cacheable_data_copiable(&tree, &None, key).await?;
        let version = self.get_balance_at_exact_topoheight(key, asset, topoheight).await?;
        Ok((topoheight, version))
    }

    // save the asset balance at specific topoheight
    async fn set_balance_at_topoheight(&mut self, asset: &Hash, topoheight: u64, key: &PublicKey, balance: &VersionedBalance) -> Result<(), BlockchainError> {
        trace!("set balance {} at topoheight {} for {}", asset, topoheight, key);
        let tree = self.get_versioned_balance_tree(asset, topoheight).await?;
        tree.insert(&key.to_bytes(), balance.to_bytes())?;
        Ok(())
    }

    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        trace!("has nonce {}", key);
        let contains = self.nonces.contains_key(key.as_bytes())?;
        Ok(contains)
    }

    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<bool, BlockchainError> {
        trace!("has nonce {} at topoheight {}", key, topoheight);
        let contains = self.get_versioned_nonce_tree(topoheight).await?.contains_key(key.as_bytes())?;
        Ok(contains)
    }

    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(u64, VersionedNonce), BlockchainError> {
        trace!("get last nonce {}", key);
        if !self.has_nonce(key).await? {
            return Err(BlockchainError::NoNonce(key.clone()))
        }

        let topoheight = self.load_from_disk(&self.nonces, key.as_bytes())?;
        Ok((topoheight, self.get_nonce_at_exact_topoheight(key, topoheight).await?))
    }

    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<VersionedNonce, BlockchainError> {
        trace!("get nonce at topoheight {} for {}", topoheight, key);
        let tree = &self.get_versioned_nonce_tree(topoheight).await?;
        self.load_from_disk(tree, &key.to_bytes())
    }

    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, topoheight: u64) -> Result<Option<(u64, VersionedNonce)>, BlockchainError> {
        trace!("get nonce at maximum topoheight {} for {}", topoheight, key);
        // check first that this address has nonce, if no returns None
        if !self.has_nonce(key).await? {
            return Ok(None)
        }

        let (topo, mut version) = self.get_last_nonce(key).await?;
        trace!("Last version of nonce for {} is at topoheight {}", key, topo);
        // if it's the latest and its under the maximum topoheight
        if topo < topoheight {
            trace!("Last version nonce (valid) found at {} (maximum topoheight = {})", topo, topoheight);
            return Ok(Some((topo, version)))
        }

        // otherwise, we have to go through the whole chain
        while let Some(previous) = version.get_previous_topoheight() {
            let previous_version = self.get_nonce_at_exact_topoheight(key, previous).await?;
            trace!("previous nonce version is at {}", previous);
            if previous < topoheight {
                trace!("Highest version nonce found at {} (maximum topoheight = {})", previous, topoheight);
                return Ok(Some((previous, previous_version)))
            }

            if let Some(value) = previous_version.get_previous_topoheight() {
                if value > previous {
                    error!("FATAL ERROR: Previous topoheight ({}) should not be higher than current version ({})!", value, previous);
                    return Err(BlockchainError::Unknown)
                }
            }
            version = previous_version;
        }

        Ok(None)
    }

    async fn set_nonce_at_topoheight(&mut self, key: &PublicKey, nonce: u64, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("set nonce to {} for {} at topo {}", nonce, key, topoheight);
        let tree = self.get_versioned_nonce_tree(topoheight).await?;
        tree.insert(&key.as_bytes(), &nonce.to_be_bytes())?;
        self.set_last_topoheight_for_nonce(key, topoheight)?;
        Ok(())
    }

    fn set_last_topoheight_for_nonce(&mut self, key: &PublicKey, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("set last topoheight for nonce {} to {}", key, topoheight);
        self.nonces.insert(&key.as_bytes(), &topoheight.to_be_bytes())?;
        Ok(())
    }

    fn get_block_reward_at_topo_height(&self, topoheight: u64) -> Result<u64, BlockchainError> {
        trace!("get block reward at topo height {}", topoheight);
        Ok(self.load_from_disk(&self.rewards, &topoheight.to_be_bytes())?)
    }

    fn set_block_reward_at_topo_height(&mut self, topoheight: u64, reward: u64) -> Result<(), BlockchainError> {
        trace!("set block reward to {} at topo height {}", reward, topoheight);
        self.rewards.insert(topoheight.to_be_bytes(), &reward.to_be_bytes())?;
        Ok(())
    }

    async fn get_transaction(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        trace!("get transaction for hash {}", hash);
        self.get_cacheable_arc_data(&self.transactions, &self.transactions_cache, hash).await
    }

    async fn has_transaction(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.contains_data(&self.transactions, &self.transactions_cache, hash).await
    }

    fn count_transactions(&self) -> usize {
        trace!("count transactions");
        self.transactions.len()
    }

    async fn add_new_block(&mut self, block: Arc<BlockHeader>, txs: &Vec<Immutable<Transaction>>, difficulty: Difficulty, hash: Hash) -> Result<(), BlockchainError> {
        debug!("Storing new {} with hash: {}, difficulty: {}", block, hash, difficulty);

        // Store transactions
        for (hash, tx) in block.get_transactions().iter().zip(txs) { // first save all txs, then save block
            if !self.has_transaction(hash).await? {
                self.transactions.insert(hash.as_bytes(), tx.to_bytes())?;
            }
        }

        // Store block header
        self.blocks.insert(hash.as_bytes(), block.to_bytes())?;

        // Store difficulty
        self.difficulty.insert(hash.as_bytes(), &difficulty.to_be_bytes())?;

        self.add_block_hash_at_height(hash.clone(), block.get_height()).await?;

        if let Some(cache) = &self.blocks_cache {
            cache.lock().await.put(hash, block);
        }

        Ok(())
    }

    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: u64, count: u64) -> Result<(u64, u64, Vec<(Hash, Arc<Transaction>)>), BlockchainError> {
        let current_topoheight = topoheight;
        trace!("pop blocks from height: {}, topoheight: {}, count: {}", height, topoheight, count);
        if height < count as u64 { // also prevent removing genesis block
            return Err(BlockchainError::NotEnoughBlocks);
        }

        // search the lowest topo height available based on count + 1
        // (last lowest topo height accepted)
        let mut lowest_topo = topoheight - count;
        trace!("Lowest topoheight for rewind: {}", lowest_topo);

        let pruned_topoheight = self.get_pruned_topoheight()?.unwrap_or(0);
        if lowest_topo < pruned_topoheight {
            warn!("Pruned topoheight is {}, lowest topoheight is {}, rewind only until {}", pruned_topoheight, lowest_topo, pruned_topoheight);
            lowest_topo = pruned_topoheight;
        }

        // new TIPS for chain
        let mut tips = self.get_tips().await?;
        // all txs to be rewinded
        let mut txs = Vec::new();
        let mut done = 0;
        'main: loop {
            // stop rewinding if its genesis block or if we reached the lowest topo
            if topoheight <= lowest_topo || topoheight == 0 || height == 0 { // prevent removing genesis block
                trace!("Done: {done}, count: {count}, height: {height}, topoheight: {topoheight}");
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

            topoheight -= 1;
            // height of old block become new height
            if block.get_height() < height {
                height = block.get_height();
            }
            done += 1;
        }

        debug!("Blocks processed {}, new topoheight: {}, new height: {}, tips: {}", done, topoheight, height, tips.len());

        // clean all assets
        let mut deleted_assets = HashSet::new();
        let mut assets = HashSet::new();
        for el in self.assets.iter() {
            let (key, value) = el?;
            let asset = Hash::from_bytes(&key)?;
            let registration_topoheight = u64::from_bytes(&value)?;
            if registration_topoheight > topoheight {
                trace!("Asset {} was registered at topoheight {}, deleting", asset, registration_topoheight);
                self.assets.remove(&key)?;
                deleted_assets.insert(asset);

                // drop the tree for this asset
                self.db.drop_tree(key)?;
            } else {
                assets.insert(asset);
            }
        }

        // now let's process nonces versions
        // we set the new highest topoheight to the highest found under the new topoheight
        for el in self.nonces.iter() {
            let (key, value) = el?;
            let highest_topoheight = u64::from_bytes(&value)?;
            if highest_topoheight > topoheight {
                self.nonces.remove(&key)?;
                // find the first version which is under topoheight
                let pkey = PublicKey::from_bytes(&key)?;
                let mut version = self.get_nonce_at_exact_topoheight(&pkey, highest_topoheight).await?;
                while let Some(previous_topoheight) = version.get_previous_topoheight() {
                    if previous_topoheight < topoheight {
                        // we find the new highest version which is under new topoheight
                        trace!("New highest version nonce for {} is at topoheight {}", pkey, previous_topoheight);
                        self.nonces.insert(&key, &previous_topoheight.to_be_bytes())?;
                        break;
                    }

                    // keep searching
                    version = self.get_nonce_at_exact_topoheight(&pkey, previous_topoheight).await?;
                }
            } else {
                // nothing to do as its under the rewinded topoheight
            }
        }

        // do balances too
        for asset in &assets {
            let tree = self.db.open_tree(asset.as_bytes())?;
            for el in tree.iter() {
                let (key, value) = el?;
                let highest_topoheight = u64::from_bytes(&value)?;
                if highest_topoheight > topoheight {
                    // find the first version which is under topoheight
                    let pkey = PublicKey::from_bytes(&key)?;
                    let mut delete = true;
                    let mut version = self.get_balance_at_exact_topoheight(&pkey, asset, highest_topoheight).await?;
                    while let Some(previous_topoheight) = version.get_previous_topoheight() {
                        if previous_topoheight < topoheight {
                            // we find the new highest version which is under new topoheight
                            trace!("New highest version balance for {} is at topoheight {} with asset {}", pkey, previous_topoheight, asset);
                            tree.insert(&key, &previous_topoheight.to_be_bytes())?;
                            delete = false;
                            break;
                        }
    
                        // keep searching
                        version = self.get_balance_at_exact_topoheight(&pkey, asset, previous_topoheight).await?;
                    }

                    if delete {
                        tree.remove(&key)?;
                    }
                } else {
                    // nothing to do as its under the rewinded topoheight
                }
            }
        }

        // now delete all versioned trees for assets and nonces
        for topoheight in topoheight..=current_topoheight {
            // delete all versioned balances for assets (deleted assets and existing assets)
            for asset in deleted_assets.iter().chain(&assets) {
                self.delete_versioned_balances_for_asset_at_topoheight(asset, topoheight).await?;
            }

            self.delete_versioned_nonces_at_topoheight(topoheight).await?;
        }

        // Clear all caches to not have old data after rewind
        self.clear_caches().await;

        // store the new tips and topo topoheight
        self.store_tips(&tips)?;
        self.set_top_topoheight(topoheight)?;
        self.set_top_height(height)?;

        // reverse order of txs so its ascending order
        txs.reverse();

        Ok((height, topoheight, txs))
    }

    fn has_blocks(&self) -> bool {
        trace!("has blocks");
        !self.blocks.is_empty()
    }

    fn count_blocks(&self) -> usize {
        trace!("count blocks");
        self.blocks.len()
    }

    async fn has_block(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has block {}", hash);
        self.contains_data(&self.blocks, &self.blocks_cache, hash).await
    }

    async fn get_block_header_at_topoheight(&self, topoheight: u64) -> Result<(Hash, Arc<BlockHeader>), BlockchainError> {
        trace!("get block at topoheight: {}", topoheight);
        let hash = self.get_hash_at_topo_height(topoheight).await?;
        let block = self.get_block_header_by_hash(&hash).await?;
        Ok((hash, block))
    }

    async fn get_block(&self, hash: &Hash) -> Result<Block, BlockchainError> {
        trace!("get block {}", hash);
        let block = self.get_block_header_by_hash(hash).await?;
        let mut transactions = Vec::new();
        for tx in block.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let block = Block::new(Immutable::Arc(block), transactions);
        Ok(block)
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

    async fn has_blocks_at_height(&self, height: u64) -> Result<bool, BlockchainError> {
        trace!("get blocks at height {}", height);
        Ok(self.blocks_at_height.contains_key(&height.to_be_bytes())?)
    }

    async fn set_blocks_at_height(&self, tips: Tips, height: u64) -> Result<(), BlockchainError> {
        trace!("set {} blocks at height {}", tips.len(), height);
        self.blocks_at_height.insert(height.to_be_bytes(), tips.to_bytes())?;
        Ok(())
    }

    // returns all blocks hash at specified height
    async fn get_blocks_at_height(&self, height: u64) -> Result<Tips, BlockchainError> {
        trace!("get blocks at height {}", height);
        self.load_from_disk(&self.blocks_at_height, &height.to_be_bytes())
    }

    async fn add_block_hash_at_height(&mut self, hash: Hash, height: u64) -> Result<(), BlockchainError> {
        trace!("add block {} at height {}", hash, height);
        let mut tips = if self.has_blocks_at_height(height).await? {
            let hashes = self.get_blocks_at_height(height).await?;
            trace!("Found {} blocks at this height", hashes.len());
            hashes
        } else {
            trace!("No blocks found at this height");
            Tips::new()
        };

        tips.insert(hash);
        self.set_blocks_at_height(tips, height).await
    }

    async fn remove_block_hash_at_height(&self, hash: &Hash, height: u64) -> Result<(), BlockchainError> {
        trace!("remove block {} at height {}", hash, height);
        let mut tips = self.get_blocks_at_height(height).await?;
        tips.remove(hash);

        // Delete the height if there is no blocks present anymore
        if tips.is_empty() {
            self.blocks_at_height.remove(&height.to_be_bytes())?;
        } else {
            self.set_blocks_at_height(tips, height).await?;
        }

        Ok(())
    }

    async fn set_topo_height_for_block(&mut self, hash: &Hash, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("set topo height for {} at {}", hash, topoheight);
        self.topo_by_hash.insert(hash.as_bytes(), topoheight.to_bytes())?;
        self.hash_at_topo.insert(topoheight.to_be_bytes(), hash.as_bytes())?;

        // save in cache
        if let Some(cache) = &self.topo_by_hash_cache {
            let mut topo = cache.lock().await;
            topo.put(hash.clone(), topoheight);
        }

        if let Some(cache) = &self.hash_at_topo_cache {
            let mut hash_at_topo = cache.lock().await;
            hash_at_topo.put(topoheight, hash.clone());
        }

        Ok(())
    }

    async fn is_block_topological_ordered(&self, hash: &Hash) -> bool {
        trace!("is block topological ordered: {}", hash);
        let topoheight = match self.get_topo_height_for_hash(&hash).await {
            Ok(topoheight) => topoheight,
            Err(e) => {
                trace!("Error while checking if block {} is ordered: {}", hash, e);
                return false
            }
        };

        let hash_at_topo = match self.get_hash_at_topo_height(topoheight).await {
            Ok(hash_at_topo) => hash_at_topo,
            Err(e) => {
                trace!("Error while checking if a block hash is ordered at topo {}: {}", topoheight, e);
                return false
            }
        };
        hash_at_topo == *hash
    }

    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        trace!("get topoheight for hash: {}", hash);
        self.get_cacheable_data_copiable(&self.topo_by_hash, &self.topo_by_hash_cache, &hash).await
    }

    async fn get_hash_at_topo_height(&self, topoheight: u64) -> Result<Hash, BlockchainError> {
        trace!("get hash at topoheight: {}", topoheight);
        let hash = if let Some(cache) = &self.hash_at_topo_cache {
            let mut hash_at_topo = cache.lock().await;
            if let Some(value) = hash_at_topo.get(&topoheight) {
                return Ok(value.clone())
            }
            let hash: Hash = self.load_from_disk(&self.hash_at_topo, &topoheight.to_be_bytes())?;
            hash_at_topo.put(topoheight, hash.clone());
            hash
        } else {
            self.load_from_disk(&self.hash_at_topo, &topoheight.to_be_bytes())?
        };

        Ok(hash)
    }

    async fn get_supply_at_topo_height(&self, topoheight: u64) -> Result<u64, BlockchainError> {
        trace!("get supply at topo height {}", topoheight);
        self.load_from_disk(&self.supply, &topoheight.to_be_bytes())
    }

    fn set_supply_at_topo_height(&mut self, topoheight: u64, supply: u64) -> Result<(), BlockchainError> {
        trace!("set supply at topo height {}", topoheight);
        self.supply.insert(topoheight.to_be_bytes(), &supply.to_be_bytes())?;
        Ok(())
    }

    async fn set_cumulative_difficulty_for_block_hash(&mut self, hash: &Hash, cumulative_difficulty: Difficulty) -> Result<(), BlockchainError> {
        trace!("set cumulative difficulty for hash {}", hash);
        self.cumulative_difficulty.insert(hash.as_bytes(), cumulative_difficulty.to_bytes())?;
        Ok(())
    }
}