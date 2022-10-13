use crate::core::immutable::Immutable;
use crate::crypto::key::PublicKey;
use crate::crypto::hash::Hash;
use super::account::Account;
use super::reader::{Reader, ReaderError};
use super::block::{CompleteBlock, Block};
use super::transaction::Transaction;
use super::serializer::Serializer;
use super::error::{BlockchainError, DiskContext};
use super::writer::Writer;
use std::collections::HashSet;
use std::hash::Hash as StdHash;
use tokio::sync::Mutex;
use std::sync::Arc;
use lru::LruCache;
use sled::Tree;
use log::{error, debug};

const TIPS: &[u8; 4] = b"TIPS";
const TOP_TOPO_HEIGHT: &[u8; 4] = b"TOPO";

pub type Tips = HashSet<Hash>;

impl Serializer for Tips {
    fn write(&self, writer: &mut Writer) {
        for hash in self {
            writer.write_hash(hash);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let total_size = reader.total_size();
        if total_size % 32 != 0 {
            return Err(ReaderError::InvalidSize)
        }

        let count = total_size % 32;
        let mut tips = HashSet::with_capacity(count);
        for _ in 0..=count {
            tips.insert(reader.read_hash()?);
        }
        Ok(tips)
    }
}

impl Serializer for u64 {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(self);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(reader.read_u64()?)
    }
}

pub struct BlockMetadata {
    difficulty: u64,
    cumulative_difficulty: u64,
    supply: u64,
    burned: u64,
    height: u64
}

impl BlockMetadata {
    pub fn new(difficulty: u64, cumulative_difficulty: u64, supply: u64, burned: u64, height: u64) -> Self {
        Self {
            difficulty,
            cumulative_difficulty,
            supply,
            burned,
            height
        }
    }

    pub fn get_difficulty(&self) -> u64 {
        self.difficulty
    }

    pub fn get_cumulative_difficulty(&self) -> u64 {
        self.cumulative_difficulty
    }

    pub fn get_supply(&self) -> u64 {
        self.supply
    }
    
    pub fn get_burned_supply(&self) -> u64 {
        self.burned
    }

    pub fn get_height(&self) -> u64 {
        self.height
    }
}

impl Serializer for BlockMetadata {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.difficulty);
        writer.write_u64(&self.cumulative_difficulty);
        writer.write_u64(&self.supply);
        writer.write_u64(&self.burned);
        writer.write_u64(&self.height);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let difficulty = reader.read_u64()?;
        let cumulative_difficulty = reader.read_u64()?;
        let supply = reader.read_u64()?;
        let burned = reader.read_u64()?;
        let height = reader.read_u64()?;

        Ok(Self::new(difficulty, cumulative_difficulty, supply, burned, height))
    }
}

pub struct Storage {
    transactions: Tree, // all txs stored on disk
    accounts: Tree, // all accounts registered on disk
    blocks: Tree, // all blocks on disk
    metadata: Tree,
    blocks_at_height: Tree, // all blocks height at specific height
    extra: Tree, // all extra data saved on disk
    topo_by_hash: Tree, // topo at hash on disk
    hash_at_topo: Tree, // hash at topo height on disk
    // cached in memory
    transactions_cache: Mutex<LruCache<Hash, Arc<Transaction>>>,
    blocks_cache: Mutex<LruCache<Hash, Arc<Block>>>,
    // Only accounts can be updated
    accounts_cache: Mutex<LruCache<PublicKey, Arc<Account>>>,
    metadata_cache: Mutex<LruCache<Hash, Arc<BlockMetadata>>>,
    past_blocks_cache: Mutex<LruCache<Hash, Arc<Vec<Hash>>>>, // previous blocks saved at each new block
    topo_by_hash_cache: Mutex<LruCache<Hash, u64>>,
    hash_at_topo_cache: Mutex<LruCache<u64, Hash>>,
    tips_cache: Tips
}

impl Storage {
    pub fn new(dir_path: String) -> Result<Self, BlockchainError> {
        let sled = sled::open(dir_path)?;
        let mut storage = Self {
            transactions: sled.open_tree("transactions")?,
            accounts: sled.open_tree("accounts")?,
            blocks: sled.open_tree("blocks")?,
            metadata: sled.open_tree("metadata")?,
            blocks_at_height: sled.open_tree("blocks_at_height")?,
            extra: sled.open_tree("extra")?,
            topo_by_hash: sled.open_tree("topo_at_hash")?,
            hash_at_topo: sled.open_tree("hash_at_topo")?,
            transactions_cache: Mutex::new(LruCache::new(1024)),
            accounts_cache: Mutex::new(LruCache::new(1024)),
            blocks_cache: Mutex::new(LruCache::new(1024)),
            metadata_cache: Mutex::new(LruCache::new(1024)),
            past_blocks_cache: Mutex::new(LruCache::new(1024)),
            topo_by_hash_cache: Mutex::new(LruCache::new(1024)),
            hash_at_topo_cache: Mutex::new(LruCache::new(1024)),
            tips_cache: HashSet::new()
        };
        
        if let Ok(tips) = storage.load_from_disk::<Tips>(&storage.extra, TIPS) {
            debug!("Found tips: {}", tips.len());
            storage.tips_cache = tips;
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

    async fn get_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Mutex<LruCache<K, Arc<V>>>, key: &K) -> Result<Arc<V>, BlockchainError> {
        let mut cache = cache.lock().await;
        if let Some(value) = cache.get(key) {
            return Ok(Arc::clone(&value));
        }

        let value = Arc::new(self.load_from_disk(tree, &key.to_bytes())?);
        cache.put(key.clone(), Arc::clone(&value));
        Ok(value)
    }

    async fn delete_data<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Mutex<LruCache<K, Arc<V>>>, key: &K) -> Result<Arc<V>, BlockchainError> {
        let bytes = match tree.remove(key.to_bytes())? {
            Some(data) => data.to_vec(),
            None => return Err(BlockchainError::NotFoundOnDisk(DiskContext::DeleteData))
        };

        let mut cache = cache.lock().await;
        if let Some(value) = cache.pop(key) {
            return Ok(value);
        }

        let mut reader = Reader::new(&bytes);
        let value = V::read(&mut reader)?;
        Ok(Arc::new(value))
    }

    async fn delete_data_no_arc<K: Eq + StdHash + Serializer + Clone, V: Serializer>(&self, tree: &Tree, cache: &Mutex<LruCache<K, V>>, key: &K) -> Result<V, BlockchainError> {
        let bytes = match tree.remove(key.to_bytes())? {
            Some(data) => data.to_vec(),
            None => return Err(BlockchainError::NotFoundOnDisk(DiskContext::DeleteData))
        };

        let mut cache = cache.lock().await;
        if let Some(value) = cache.pop(key) {
            return Ok(value);
        }

        let mut reader = Reader::new(&bytes);
        let value = V::read(&mut reader)?;
        Ok(value)
    }

    pub async fn has_account(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        Ok(self.accounts_cache.lock().await.contains(key) || self.accounts.contains_key(key.as_bytes())?)
    }

    pub async fn get_account(&self, key: &PublicKey) -> Result<Arc<Account>, BlockchainError> {
        self.get_data(&self.accounts, &self.accounts_cache, key).await
    }

    // save directly on disk & in cache
    pub async fn register_account(&mut self, key: PublicKey) -> Result<(), BlockchainError> {
        let account = Account::new(0, 0);

        self.accounts.insert(key.as_bytes(), account.to_bytes())?;
        let mut accounts = self.accounts_cache.lock().await;
        accounts.put(key, Arc::new(account));

        Ok(())
    }

    pub fn count_accounts(&self) -> usize {
        self.accounts.len()
    }

    pub async fn get_transaction(&self, hash: &Hash) -> Result<Arc<Transaction>, BlockchainError> {
        self.get_data(&self.transactions, &self.transactions_cache, hash).await
    }

    pub fn count_transactions(&self) -> usize {
        self.transactions.len()
    }

    pub async fn add_new_block(&mut self, block: Arc<Block>, txs: &Vec<Immutable<Transaction>>, difficulty: u64, hash: Hash, cumulative_difficulty: u64, supply: u64, burned: u64) -> Result<(), BlockchainError> {
        for (hash, tx) in block.get_transactions().iter().zip(txs) { // first save all txs, then save block
            self.transactions.insert(hash.as_bytes(), tx.to_bytes())?;
        }
        self.blocks.insert(hash.as_bytes(), block.to_bytes())?;

        let metadata = BlockMetadata::new(difficulty, cumulative_difficulty, supply, burned, block.get_height());
        self.metadata.insert(hash.as_bytes(), metadata.to_bytes())?;

        self.add_block_hash_at_height(hash.clone(), block.get_height()).await?;

        self.metadata_cache.lock().await.put(hash.clone(), Arc::new(metadata));
        self.blocks_cache.lock().await.put(hash, block);

        Ok(())
    }

    pub async fn pop_blocks(&mut self, current_height: u64, n: u64) -> Result<(u64, u64, Arc<BlockMetadata>), BlockchainError> {
        if current_height <= n as u64 { // also prevent removing genesis block
            return Err(BlockchainError::NotEnoughBlocks);
        }

        for i in current_height..n {
            debug!("Deleting block at topoheight {}", i);
            let block_hash = self.delete_data_no_arc(&self.hash_at_topo, &self.hash_at_topo_cache, &(current_height - i)).await?;
            self.delete_data_no_arc(&self.topo_by_hash, &self.topo_by_hash_cache, &block_hash).await?;

            self.delete_data(&self.metadata, &self.metadata_cache, &block_hash).await?;
            let block = self.delete_data(&self.blocks, &self.blocks_cache, &block_hash).await?;
            for tx in block.get_transactions() {
                self.delete_data(&self.transactions, &self.transactions_cache, tx).await?;
                // TODO revert TXs
            }
        }

        let (top_hash, metadata) = self.get_top_metadata().await?;
        let new_height = metadata.get_height();
        if new_height != current_height - n {
            error!("Error on pop blocks ! height: {}, n: {}, new height: {}", current_height, n, new_height);
        }
        let topoheight = self.get_topo_height_for_hash(&top_hash).await?;
        Ok((new_height, topoheight, metadata))
    }

    pub fn has_blocks(&self) -> bool {
        !self.blocks.is_empty()
    }

    pub fn count_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub async fn has_block(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.blocks_cache.lock().await.contains(hash) || self.blocks.contains_key(hash.as_bytes())?)
    }

    pub async fn get_block_by_hash(&self, hash: &Hash) -> Result<Arc<Block>, BlockchainError> {
        self.get_data(&self.blocks, &self.blocks_cache, hash).await
    }

    pub async fn get_block_metadata_by_hash(&self, hash: &Hash) -> Result<Arc<BlockMetadata>, BlockchainError> {
        self.get_data(&self.metadata, &self.metadata_cache, hash).await
    }


    pub async fn get_block_at_topoheight(&self, topoheight: u64) -> Result<(Hash, Arc<Block>), BlockchainError> {
        let hash = self.get_hash_at_topo_height(topoheight).await?;
        let block = self.get_data(&self.blocks, &self.blocks_cache, &hash).await?;
        Ok((hash, block))
    }

    pub async fn get_complete_block(&self, hash: &Hash) -> Result<CompleteBlock, BlockchainError> {
        let block = self.get_block_by_hash(hash).await?;
        let mut transactions = Vec::new();
        for tx in block.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let complete_block = CompleteBlock::new(Immutable::Arc(block), transactions);
        Ok(complete_block)
    }

    pub async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        self.get_hash_at_topo_height(self.get_top_topoheight()?).await
    }

    pub fn get_top_topoheight(&self) -> Result<u64, BlockchainError> {
        self.load_from_disk(&self.extra, TOP_TOPO_HEIGHT)
    }

    pub fn set_top_topoheight(&self, topoheight: u64) -> Result<(), BlockchainError> {
        self.extra.insert(TOP_TOPO_HEIGHT, &topoheight.to_be_bytes())?;
        Ok(())
    }

    pub async fn get_top_metadata(&self) -> Result<(Hash, Arc<BlockMetadata>), BlockchainError> {   
        let topoheight = self.get_top_topoheight()?;
        let hash = self.get_hash_at_topo_height(topoheight).await?;
        let metadata = self.get_block_metadata_by_hash(&hash).await?;
        debug!("Top block hash is {} at height {} and topoheight {}", hash, metadata.get_height(), topoheight);
        Ok((hash, metadata))
    }

    pub async fn get_top_complete_block(&self) -> Result<CompleteBlock, BlockchainError> {
        let (hash, _) = self.get_top_metadata().await?;
        let block = self.get_block_by_hash(&hash).await?;
        let mut transactions = Vec::new();
        for tx in block.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let complete_block = CompleteBlock::new(Immutable::Arc(block), transactions);
        Ok(complete_block)
    }

    pub async fn get_tips(&self) -> Result<Tips, BlockchainError> {
        Ok(self.tips_cache.clone())
    }

    pub fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError> {
        debug!("Saving {} Tips", tips.len());
        self.extra.insert(TIPS, tips.to_bytes())?;
        self.tips_cache = tips.clone();
        Ok(())
    }

    pub async fn get_past_blocks_of(&self, hash: &Hash) -> Result<Arc<Vec<Hash>>, BlockchainError> {
        let mut cache = self.past_blocks_cache.lock().await;
        if let Some(tips) = cache.get(hash) {
            return Ok(tips.clone())
        }

        let block = self.get_block_by_hash(hash).await?;
        let mut tips = Vec::with_capacity(block.get_tips().len());
        for hash in block.get_tips() {
            tips.push(hash.clone());
        }

        let tips = Arc::new(tips);
        cache.put(hash.clone(), tips.clone());

        Ok(tips)
    }

    // returns all blocks hash at specified height
    pub async fn get_blocks_at_height(&self, height: u64) -> Result<Tips, BlockchainError> {
        // TODO cache
        self.load_from_disk(&self.blocks_at_height, &height.to_be_bytes())
    }

    pub async fn add_block_hash_at_height(&self, hash: Hash, height: u64) -> Result<(), BlockchainError> {
        let mut tips = match self.get_blocks_at_height(height).await {
            Ok(tips) => tips,
            Err(_) => Tips::new()
        };
        tips.insert(hash);

        self.blocks_at_height.insert(height.to_be_bytes(), tips.to_bytes())?;
        Ok(())
    }

    // TODO optimize all these functions to read only what is necessary
    pub async fn get_height_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        let block = self.get_block_by_hash(hash).await?;
        Ok(block.get_height())
    }

    pub async fn set_topo_height_for_block(&self, hash: Hash, height: u64) -> Result<(), BlockchainError> {
        self.topo_by_hash.insert(hash.as_bytes(), height.to_bytes())?;
        self.hash_at_topo.insert(height.to_be_bytes(), hash.as_bytes())?;

        // save in cache
        let mut topo = self.topo_by_hash_cache.lock().await;
        let mut hash_at_topo = self.hash_at_topo_cache.lock().await;
        topo.put(hash.clone(), height);
        hash_at_topo.put(height, hash);
        Ok(())
    }

    pub async fn is_block_topological_ordered(&self, hash: &Hash) -> bool {
        let topoheight = match self.get_topo_height_for_hash(&hash).await {
            Ok(topoheight) => topoheight,
            Err(e) => {
                debug!("Error while checking if block {} is ordered: {}", hash, e);
                return false
            }
        };

        let hash_at_topo = match self.get_hash_at_topo_height(topoheight).await {
            Ok(hash_at_topo) => hash_at_topo,
            Err(e) => {
                debug!("Error while checking if a block hash is ordered at topo {}: {}", topoheight, e);
                return false
            }
        };
        hash_at_topo == *hash
    }

    // TODO generic
    pub async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        let mut topo_at_hash = self.topo_by_hash_cache.lock().await;
        if let Some(value) = topo_at_hash.get(hash) {
            return Ok(*value)
        }

        debug!("Trying to read topo of hash {}", hash);
        let height = self.load_from_disk(&self.topo_by_hash, hash.as_bytes())?;
        topo_at_hash.put(hash.clone(), height);
        Ok(height)
    }

    pub async fn get_hash_at_topo_height(&self, height: u64) -> Result<Hash, BlockchainError> {
        let mut hash_at_topo = self.hash_at_topo_cache.lock().await;
        if let Some(value) = hash_at_topo.get(&height) {
            return Ok(value.clone())
        }

        let hash: Hash = self.load_from_disk(&self.hash_at_topo, &height.to_be_bytes())?;
        hash_at_topo.put(height, hash.clone());
        Ok(hash)
    }

    pub async fn get_difficulty_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        let metadata = self.get_block_metadata_by_hash(hash).await?;
        Ok(metadata.get_difficulty())
    }

    pub async fn get_timestamp_for_block(&self, hash: &Hash) -> Result<u128, BlockchainError> {
        let block = self.get_block_by_hash(hash).await?;
        Ok(block.get_timestamp())
    }

    pub async fn get_cumulative_difficulty_for_block(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        let metadata = self.get_block_metadata_by_hash(hash).await?;
        Ok(metadata.get_cumulative_difficulty())
    }
}