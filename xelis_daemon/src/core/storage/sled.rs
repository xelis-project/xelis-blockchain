use async_trait::async_trait;
use crate::core::error::{BlockchainError, DiskContext};
use xelis_common::{
    serializer::{Reader, Serializer},
    crypto::{key::PublicKey, hash::{Hash, hash}},
    immutable::Immutable,
    transaction::Transaction,
    block::{BlockHeader, Block, Difficulty}, account::VersionedBalance, network::Network,
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
const PRUNED_HEIGHT: &[u8; 4] = b"PRUN";

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
    rewards: Tree, // all block rewards for blocks
    supply: Tree, // supply for each block hash
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
    nonces_cache: Option<Mutex<LruCache<PublicKey, u64>>>,
    balances_trees_cache: Option<Mutex<LruCache<u64, Tree>>>, // versioned balances tree keep in cache to prevent hash recompute
    tips_cache: Tips,
    pruned_height: Option<u64>
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
            nonces_cache: init_cache!(cache_size),
            balances_trees_cache: init_cache!(cache_size),
            tips_cache: HashSet::new(),
            pruned_height: None
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

        if let Ok(pruned_height) = storage.load_from_disk::<u64>(&storage.extra, PRUNED_HEIGHT) {
            debug!("Found pruned height: {}", pruned_height);
            storage.pruned_height = Some(pruned_height);
        }

        Ok(storage)
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

    async fn get_arc_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, Arc<V>>>>, key: &K) -> Result<Arc<V>, BlockchainError> {
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

    async fn get_data<K: Eq + StdHash + Serializer + Clone, V: Serializer + Copy>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<V, BlockchainError> {
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

    async fn delete_data_no_arc<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Option<Mutex<LruCache<K, V>>>, key: &K) -> Result<V, BlockchainError> {
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
            if let Some(tree) = balances.get(&topoheight) {
                tree.clone()
            } else { // not found in cache, compute it and insert it
                let key = self.generate_versioned_balance_key(asset, topoheight)?;
                let tree = self.db.open_tree(key.as_bytes())?;
                balances.put(topoheight, tree.clone());
                tree
            }
        } else { // no cache found, we have to compute it ourself
            let key = self.generate_versioned_balance_key(asset, topoheight)?;
            self.db.open_tree(key.as_bytes())?
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
        self.get_data(&self.cumulative_difficulty, &self.cumulative_difficulty_cache, hash).await
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
        self.get_arc_data(&self.blocks, &self.blocks_cache, hash).await
    }
}

#[async_trait]
impl Storage for SledStorage {
    fn get_pruned_height(&self) -> Result<Option<u64>, BlockchainError> {
        Ok(self.pruned_height)
    }

    fn set_pruned_height(&mut self, pruned_height: u64) -> Result<(), BlockchainError> {
        self.pruned_height = Some(pruned_height);
        self.extra.insert(PRUNED_HEIGHT, &pruned_height.to_be_bytes())?;
        Ok(())
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

    async fn add_asset(&mut self, asset: &Hash) -> Result<(), BlockchainError> {
        trace!("add asset {}", asset);
        self.assets.insert(asset.as_bytes(), &[0u8; 0])?;
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
        for e in self.assets.iter() {
            let (key, _) = e?;
            let mut reader = Reader::new(&key);
            let hash = Hash::read(&mut reader)?;
            assets.push(hash);
        }

        Ok(assets)
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

    fn add_block_for_tx(&mut self, tx: &Hash, block: Hash) -> Result<(), BlockchainError> {
        trace!("add block {} for tx {}", block, tx);
        let mut blocks = if self.has_tx_blocks(tx)? {
            self.get_blocks_for_tx(tx)?
        } else {
            Tips::new()
        };

        if !blocks.contains(&block) {
            blocks.insert(block);
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

    // returns the highest topoheight where a balance changes happened
    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<u64, BlockchainError> {
        trace!("get last topoheight for balance {} for {}", asset, key);
        if !self.has_balance_for(key, asset).await? {
            return Ok(0)
        }

        let tree = self.db.open_tree(asset.as_bytes())?;
        self.get_data(&tree, &None, key).await
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
            return Err(BlockchainError::NoBalanceChanges(key.clone()))
        }

        let tree = self.get_versioned_balance_tree(asset, topoheight).await?;
        self.contains_data::<PublicKey, ()>(&tree, &None, key).await
    }

    // get the balance at a specific topoheight
    // if there is no balance change at this topoheight just return an error
    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError> {
        trace!("get balance {} for {} at exact topoheight {}", asset, key, topoheight);
        // check first that this address has balance, if no returns
        if !self.has_balance_for(key, asset).await? {
            return Err(BlockchainError::NoBalanceChanges(key.clone()))
        }

        let tree = self.get_versioned_balance_tree(asset, topoheight).await?;
        self.get_data(&tree, &None, key).await.map_err(|_| BlockchainError::NoBalanceChanges(key.clone()))
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
    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<Option<(u64, VersionedBalance)>, BlockchainError> {
        trace!("get balance {} for {} at maximum topoheight {}", asset, key, topoheight);
        // check first that this address has balance for this asset, if no returns None
        if !self.has_balance_for(key, asset).await? {
            return Ok(None)
        }

        let (topo, mut version) = self.get_last_balance(key, asset).await?;
        trace!("Last version balance {} for {} is at topoheight {}", asset, key, topo);
        // if it's the latest and its under the maximum topoheight
        if topo < topoheight {
            trace!("Last version balance (valid) found at {} (maximum topoheight = {})", topo, topoheight);
            return Ok(Some((topo, version)))
        }

        // otherwise, we have to go through the whole chain
        while let Some(previous) = version.get_previous_topoheight() {
            let previous_version = self.get_balance_at_exact_topoheight(key, asset, previous).await?;
            trace!("previous version {}", previous);
            if previous < topoheight {
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
        self.delete_data_no_arc(&tree, &None, key).await.map_err(|_| BlockchainError::NoBalanceChanges(key.clone()))
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
        let topoheight = self.get_data(&tree, &None, key).await?;
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
        self.contains_data(&self.nonces, &self.nonces_cache, key).await
    }

    async fn get_nonce(&self, key: &PublicKey) -> Result<u64, BlockchainError> {
        trace!("get nonce {}", key);
        if !self.has_nonce(key).await? {
            return Ok(0)
        }

        self.get_data(&self.nonces, &self.nonces_cache, key).await
    }

    async fn set_nonce(&mut self, key: &PublicKey, nonce: u64) -> Result<(), BlockchainError> {
        trace!("set nonce to {} for {}", nonce, key);
        self.nonces.insert(&key.as_bytes(), &nonce.to_be_bytes())?;
        if let Some(cache) = &self.nonces_cache {
            let mut cache = cache.lock().await;
            cache.put(key.clone(), nonce);
        }

        Ok(())
    }

    fn get_block_reward(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        trace!("get block reward for {}", hash);
        Ok(self.load_from_disk(&self.rewards, hash.as_bytes())?)
    }

    fn set_block_reward(&mut self, hash: &Hash, reward: u64) -> Result<(), BlockchainError> {
        trace!("set block reward for {} to {}", hash, reward);
        self.rewards.insert(hash.as_bytes(), &reward.to_be_bytes())?;
        Ok(())
    }

    async fn get_transaction(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        trace!("get transaction for hash {}", hash);
        self.get_arc_data(&self.transactions, &self.transactions_cache, hash).await
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

    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: u64, count: u64) -> Result<(u64, u64, Vec<(Hash, Arc<Transaction>)>, HashSet<PublicKey>), BlockchainError> {
        trace!("pop blocks from height: {}, topoheight: {}, count: {}", height, topoheight, count);
        if height < count as u64 { // also prevent removing genesis block
            return Err(BlockchainError::NotEnoughBlocks);
        }

        // search the lowest topo height available based on count + 1
        // (last lowest topo height accepted)
        let mut lowest_topo = topoheight;
        trace!("search lowest topo height available, height = {}, count = {}", height, count);
        for i in (height-count..=height).rev() {
            trace!("checking lowest topoheight for blocks at {}", i);
            if self.has_blocks_at_height(i).await? {
                for hash in self.get_blocks_at_height(i).await? {
                    if self.is_block_topological_ordered(&hash).await {
                        let topo = self.get_topo_height_for_hash(&hash).await?;
                        if topo < lowest_topo {
                            lowest_topo = topo;
                        }
                    }
                }
            } else {
                warn!("No blocks found at {}, how ?", i);
            }
        }
        trace!("Lowest topoheight for rewind: {}", lowest_topo);

        // new TIPS for chain
        let mut tips = self.get_tips().await?;
        // all txs to be rewinded
        let mut txs = Vec::new();
        // all miners rewards to be rewinded
        let mut miners: HashSet<PublicKey> = HashSet::new();
        let mut done = 0;
        'main: loop {
            // check if the next block is alone at its height, if yes stop rewinding
            if done >= count || height == 0 { // prevent removing genesis block
                let tmp_blocks_at_height = self.get_blocks_at_height(height).await?;
                if tmp_blocks_at_height.len() == 1 {
                    for unique in tmp_blocks_at_height {
                        if self.is_block_topological_ordered(&unique).await {
                            topoheight = self.get_topo_height_for_hash(&unique).await?;
                            if topoheight <= lowest_topo {
                                trace!("Unique block at height {} and topoheight {} found!", height, topoheight);
                                break 'main;
                            }
                        }
                    }
                }
            }

            // get all blocks at same height, and delete current block hash from the list
            trace!("Searching blocks at height {}", height);
            let blocks_at_height: Tips = self.delete_data_no_arc(&self.blocks_at_height, &None, &height).await?;
            trace!("Blocks at height {}: {}", height, blocks_at_height.len());

            for hash in blocks_at_height {
                trace!("deleting block header {}", hash);
                let block = self.delete_data(&self.blocks, &self.blocks_cache, &hash).await?;
                trace!("block header deleted successfully");

                miners.insert(block.get_miner().clone());

                let _: Difficulty = self.delete_data_no_arc(&self.supply, &None, &hash).await?;
                let _: Difficulty = self.delete_data_no_arc(&self.difficulty, &None, &hash).await?;

                trace!("Deleting cumulative difficulty");
                let cumulative_difficulty: u64 = self.delete_data_no_arc(&self.cumulative_difficulty, &self.cumulative_difficulty_cache, &hash).await?;
                trace!("Cumulative difficulty deleted: {}", cumulative_difficulty);

                let reward: u64 = self.delete_data_no_arc(&self.rewards, &None, &hash).await?;
                trace!("Reward for block {} was: {}", hash, reward);

                for tx_hash in block.get_transactions() {
                    let tx = self.delete_data(&self.transactions, &self.transactions_cache, tx_hash).await?;
                    if self.has_tx_blocks(tx_hash)? {
                        let mut blocks: Tips = self.delete_data_no_arc(&self.tx_blocks, &None, tx_hash).await?;
                        let blocks_len =  blocks.len();
                        blocks.remove(&hash);
                        self.set_blocks_for_tx(tx_hash, &blocks)?;
                        trace!("Tx was included in {}, blocks left: {}", blocks_len, blocks.into_iter().map(|b| b.to_string()).collect::<Vec<String>>().join(", "));
                    }

                    if self.is_tx_executed_in_a_block(tx_hash)? {
                        trace!("Tx {} was executed, deleting", tx_hash);
                        self.remove_tx_executed(&tx_hash)?;
                    }

                    txs.push((tx_hash.clone(), tx));
                }

                // if block is ordered, delete data that are linked to it
                if let Ok(topo) = self.get_topo_height_for_hash(&hash).await {
                    if topo < topoheight {
                        topoheight = topo;
                    }

                    trace!("Block was at topoheight {}", topo);
                    self.delete_data_no_arc(&self.topo_by_hash, &self.topo_by_hash_cache, &hash).await?;

                    if let Ok(hash_at_topo) = self.get_hash_at_topo_height(topo).await {
                        if hash_at_topo == hash {
                            trace!("Deleting hash '{}' at topo height '{}'", hash_at_topo, topo);
                            self.delete_data_no_arc(&self.hash_at_topo, &self.hash_at_topo_cache, &topo).await?;
                        }
                    }
                }

                // generate new tips
                trace!("Removing {} from {} tips", hash, tips.len());
                tips.remove(&hash);
                trace!("Tips: {}", tips.len());
                for tip in &tips {
                    trace!("Tip {}", tip);
                }

                for hash in block.get_tips() {
                    trace!("Adding {} to {} tips", hash, tips.len());
                    tips.insert(hash.clone());
                }
            }

            // height of old block become new height
            height -= 1;
            done += 1;
        }
        debug!("Blocks processed {}, new topoheight: {}, tips: {}", done, topoheight, tips.len());
        for hash in &tips {
            trace!("hash {} at height {}", hash, self.get_height_for_block_hash(&hash).await?);
        }
        // store the new tips and topo topoheight
        self.store_tips(&tips)?;
        self.set_top_topoheight(topoheight)?;
        self.set_top_height(height)?;

        Ok((height, topoheight, txs, miners))
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

        self.blocks_at_height.insert(height.to_be_bytes(), tips.to_bytes())?;
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
        self.get_data(&self.topo_by_hash, &self.topo_by_hash_cache, &hash).await
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
        let hash = self.get_hash_at_topo_height(topoheight).await?;
        self.get_supply_for_block_hash(&hash)
    }
    
    fn get_supply_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        trace!("get supply for hash {}", hash);
        self.load_from_disk(&self.supply, hash.as_bytes())
    }

    fn set_supply_for_block_hash(&mut self, hash: &Hash, supply: u64) -> Result<(), BlockchainError> {
        trace!("set supply for hash {}", hash);
        self.supply.insert(hash.as_bytes(), &supply.to_be_bytes())?;
        Ok(())
    }

    async fn set_cumulative_difficulty_for_block_hash(&mut self, hash: &Hash, cumulative_difficulty: Difficulty) -> Result<(), BlockchainError> {
        trace!("set cumulative difficulty for hash {}", hash);
        self.cumulative_difficulty.insert(hash.as_bytes(), cumulative_difficulty.to_bytes())?;
        Ok(())
    }
}