use crate::crypto::hash::{Hash, Hashable};
use crate::crypto::key::PublicKey;
use super::error::BlockchainError;
use super::block::CompleteBlock;
use super::blockchain::Account;
use std::collections::HashMap;

pub struct Storage {
    accounts: HashMap<PublicKey, Account>, // all accounts registered on chain
    top_block_hash: Hash, // current block top hash
    blocks: Vec<CompleteBlock>, // all blocks in blockchain
}

impl Storage {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            top_block_hash: Hash::zero(),
            blocks: Vec::new()
        }
    }

    pub fn has_account(&self, account: &PublicKey) -> bool {
        self.accounts.contains_key(account)
    }

    pub fn get_account(&self, account: &PublicKey) -> Result<&Account, BlockchainError> {
        match self.accounts.get(account) {
            Some(v) => Ok(v),
            None => Err(BlockchainError::AddressNotRegistered(account.clone()))
        }
    }

    pub fn register_account(&mut self, pub_key: PublicKey){
        self.accounts.insert(pub_key, Account::new(0, 0));
    }

    pub fn get_mut_account(&mut self, account: &PublicKey) -> Result<&mut Account, BlockchainError> {
        match self.accounts.get_mut(account) {
            Some(v) => Ok(v),
            None => Err(BlockchainError::AddressNotRegistered(account.clone()))
        }
    }

    pub fn get_accounts(&self) -> &HashMap<PublicKey, Account> {
        &self.accounts
    }

    pub fn add_new_block(&mut self, block: CompleteBlock, hash: Hash) {
        self.blocks.push(block);
        self.top_block_hash = hash;
    }

    pub fn pop_blocks(&mut self, n: usize) -> Result<u64, BlockchainError> {
        if self.blocks.len() <= n { // also prevent removing genesis block
            return Err(BlockchainError::NotEnoughBlocks);
        }
        self.blocks.truncate(self.blocks.len() - n);
        let top_height = if let Some(block) = self.blocks.get(self.blocks.len() - 1) {
            let hash = block.hash();
            let height = block.get_height();
            self.top_block_hash = hash;
            // TODO Reverse txs
            height
        } else { // shouldn't happens
            self.top_block_hash = Hash::zero();
            0
        };

        Ok(top_height)
    }

    pub fn has_blocks(&self) -> bool {
        self.blocks.len() != 0
    }

    pub fn has_block(&self, hash: &Hash) -> bool {
        self.get_block_by_hash(hash).is_ok()
    }

    pub fn get_block_at_height(&self, height: u64) -> Result<&CompleteBlock, BlockchainError> {
        match self.blocks.get(height as usize - 1) {
            Some(block) => Ok(block),
            None => Err(BlockchainError::BlockHeightNotFound(height))
        }
    }

    pub fn get_block_by_hash(&self, hash: &Hash) -> Result<&CompleteBlock, BlockchainError> {
        for block in &self.blocks {
            if block.hash() == *hash {
                return Ok(&block)
            }
        }
        Err(BlockchainError::BlockNotFound(hash.clone()))
    }

    pub fn get_blocks(&self) -> &Vec<CompleteBlock> {
        &self.blocks
    }

    pub fn get_top_block_hash(&self) -> &Hash {
        &self.top_block_hash
    }

    pub fn get_top_block(&self) -> Result<&CompleteBlock, BlockchainError> {
        self.get_block_by_hash(self.get_top_block_hash())
    }
}