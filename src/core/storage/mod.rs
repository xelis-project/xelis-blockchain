use crate::core::immutable::Immutable;
use crate::crypto::key::PublicKey;
use crate::crypto::hash::{Hash};
use super::reader::{Reader, ReaderError};
use super::block::{CompleteBlock, Block};
use super::transaction::Transaction;
use super::serializer::Serializer;
use super::error::BlockchainError;
use super::blockchain::Account;
use super::writer::Writer;
use std::hash::Hash as StdHash;
use tokio::sync::Mutex;
use std::sync::Arc;
use lru::LruCache;
use sled::Tree;
use log::error;

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
    supply: u64,
    burned: u64,
    hash: Hash
}

impl BlockMetadata {
    pub fn new(difficulty: u64, supply: u64, burned: u64, hash: Hash) -> Self {
        Self {
            difficulty,
            supply,
            burned,
            hash
        }
    }

    pub fn get_difficulty(&self) -> u64 {
        self.difficulty
    }
    
    pub fn get_supply(&self) -> u64 {
        self.supply
    }
    
    pub fn get_burned_supply(&self) -> u64 {
        self.burned
    }

    pub fn get_hash(&self) -> &Hash {
        &self.hash
    }
}

impl Serializer for BlockMetadata {
    fn write(&self, writer: &mut Writer) {
        writer.write_u64(&self.difficulty);
        writer.write_u64(&self.supply);
        writer.write_u64(&self.burned);
        writer.write_hash(&self.hash);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let difficulty = reader.read_u64()?;
        let supply = reader.read_u64()?;
        let burned = reader.read_u64()?;
        let hash = reader.read_hash()?;

        Ok(Self::new(difficulty, supply, burned, hash))
    }
}

pub struct Storage {
    transactions: Tree, // all txs stored on disk
    accounts: Tree, // all accounts registered on disk
    blocks: Tree, // all blocks on disk
    metadata: Tree,
    // cached in memory
    transactions_cache: Mutex<LruCache<Hash, Arc<Transaction>>>,
    blocks_cache: Mutex<LruCache<Hash, Arc<Block>>>,
    // Only accounts can be updated
    accounts_cache: Mutex<LruCache<PublicKey, Arc<Account>>>,
    metadata_cache: Mutex<LruCache<u64, Arc<BlockMetadata>>>
}

impl Storage {
    pub fn new() -> Result<Self, BlockchainError> { // TODO configurable cache size & folder path
        let sled = sled::open("mainnet")?;
        let accounts = sled.open_tree("accounts")?;
        let transactions = sled.open_tree("transactions")?;
        let blocks = sled.open_tree("blocks")?;
        let metadata = sled.open_tree("metadata")?;

        Ok(Self {
            transactions,
            accounts,
            blocks,
            metadata,
            transactions_cache: Mutex::new(LruCache::new(1024)),
            accounts_cache: Mutex::new(LruCache::new(1024)),
            blocks_cache: Mutex::new(LruCache::new(1024)),
            metadata_cache: Mutex::new(LruCache::new(1024))
        })
    }

    fn load_from_disk<T: Serializer>(&self, tree: &Tree, key: &[u8]) -> Result<T, BlockchainError> {
        match tree.get(key)? {
            Some(bytes) => {
                let bytes = bytes.to_vec();
                let mut reader = Reader::new(&bytes);
                let value = T::read(&mut reader)?;
                Ok(value)
            },
            None => Err(BlockchainError::NotFoundOnDisk)
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
            None => return Err(BlockchainError::NotFoundOnDisk)
        };

        let mut cache = cache.lock().await;
        if let Some(value) = cache.pop(key) {
            return Ok(value);
        }

        let mut reader = Reader::new(&bytes);
        let value = V::read(&mut reader)?;
        Ok(Arc::new(value))
    }

    // flush all trees
    pub async fn flush(&self) -> Result<(), BlockchainError> {
        self.blocks.flush_async().await?;
        self.accounts.flush_async().await?;
        self.transactions.flush_async().await?;
        self.metadata.flush_async().await?;

        Ok(())
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

    pub async fn add_new_block(&mut self, block: CompleteBlock, hash: Hash, supply: u64, burned: u64) -> Result<(), BlockchainError> {
        let (block, mut txs, difficulty) = block.split();
        self.blocks.insert(hash.as_bytes(), block.to_bytes())?;
        for tx in block.get_transactions() {
            self.transactions.insert(tx.as_bytes(), txs.remove(0).to_bytes())?;
        }

        let metadata = BlockMetadata::new(difficulty, supply, burned, hash.clone()); // TODO Arc ?
        self.metadata.insert(block.get_height().to_bytes(), metadata.to_bytes())?;

        self.metadata_cache.lock().await.put(block.get_height(), Arc::new(metadata));
        self.blocks_cache.lock().await.put(hash, block.to_arc());
        //self.flush().await?;

        Ok(())
    }

    pub async fn pop_blocks(&mut self, current_height: u64, n: u64) -> Result<(u64, BlockMetadata), BlockchainError> {
        if current_height <= n as u64 { // also prevent removing genesis block
            return Err(BlockchainError::NotEnoughBlocks);
        }

        for i in current_height..n {
            let metadata = self.delete_data(&self.metadata, &self.metadata_cache, &(current_height - i)).await?;
            let block = self.delete_data(&self.blocks, &self.blocks_cache, metadata.get_hash()).await?;
            for tx in block.get_transactions() {
                self.delete_data(&self.transactions, &self.transactions_cache, tx).await?;
                // TODO revert TXs
            }
        }

        let (new_height, metadata) = self.get_top_metadata()?;
        if new_height != current_height - n {
            error!("Error on pop blocks ! height: {}, n: {}, new height: {}", current_height, n, new_height);
        }
        Ok((new_height, metadata))
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

    pub async fn get_block_metadata(&self, height: u64) -> Result<Arc<BlockMetadata>, BlockchainError> {
        self.get_data(&self.metadata, &self.metadata_cache, &height).await
    }

    pub async fn get_block_at_height(&self, height: u64) -> Result<(Hash, Arc<Block>), BlockchainError> {
        let metadata = self.get_block_metadata(height).await?;
        Ok((metadata.get_hash().clone(), self.get_data(&self.blocks, &self.blocks_cache, &metadata.hash).await?))
    }

    pub async fn get_complete_block(&self, hash: &Hash) -> Result<CompleteBlock, BlockchainError> {
        let block = self.get_block_by_hash(hash).await?;
        let metadata = self.get_block_metadata(block.get_height()).await?;
        
        let mut transactions = Vec::new();
        for tx in block.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let complete_block = CompleteBlock::new(Immutable::Arc(block), metadata.get_difficulty(), transactions);
        Ok(complete_block)
    }

    pub fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        let (_, metadata) = self.get_top_metadata()?;
        Ok(metadata.get_hash().clone()) // TODO
    }

    // TODO generic
    pub fn get_top_block(&self) -> Result<Block, BlockchainError> {
        let data = match self.blocks.last()? {
            Some((_, data)) => data,
            None => return Err(BlockchainError::NotFoundOnDisk)
        };
        let bytes = data.to_vec();
        let mut reader = Reader::new(&bytes);
        let value = Block::read(&mut reader)?;
        Ok(value)
    }

    pub fn get_top_metadata(&self) -> Result<(u64, BlockMetadata), BlockchainError> {
        let (key, value) = match self.metadata.last()? {
            Some((key, value)) => (key, value),
            None => return Err(BlockchainError::NotFoundOnDisk)
        };

        let bytes = key.to_vec();
        let mut reader = Reader::new(&bytes);
        let height = u64::read(&mut reader)?;

        let bytes = value.to_vec();
        let mut reader = Reader::new(&bytes);
        let metadata = BlockMetadata::read(&mut reader)?;
        Ok((height, metadata))
    }

    pub async fn get_top_complete_block(&self) -> Result<CompleteBlock, BlockchainError> {
        let (_, metadata) = self.get_top_metadata()?;
        let block = self.get_block_by_hash(metadata.get_hash()).await?;
        let mut transactions = Vec::new();
        for tx in block.get_transactions() {
            let transaction = self.get_transaction(tx).await?;
            transactions.push(Immutable::Arc(transaction));
        }

        let complete_block = CompleteBlock::new(Immutable::Arc(block), metadata.get_difficulty(), transactions);
        Ok(complete_block)
    }
}