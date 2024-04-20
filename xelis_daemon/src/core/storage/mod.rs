mod providers;
mod sled;

pub use self::{
    sled::SledStorage,
    providers::*,
};

use std::{collections::HashSet, sync::Arc};
use async_trait::async_trait;
use xelis_common::{
    block::{Block, BlockHeader},
    crypto::Hash,
    network::Network,
    transaction::Transaction,
};
use crate::core::error::BlockchainError;

// Represents the tips of the chain or of a block
pub type Tips = HashSet<Hash>;

#[async_trait]
pub trait Storage: DagOrderProvider + PrunedTopoheightProvider + NonceProvider + AccountProvider + ClientProtocolProvider + BlockDagProvider + MerkleHashProvider + Sync + Send + 'static {
    // Is the chain running on mainnet
    fn is_mainnet(&self) -> bool;

    // Clear caches if exists
    async fn clear_caches(&mut self) -> Result<(), BlockchainError>;

    // delete block at topoheight, and all pointers (hash_at_topo, topo_by_hash, reward, supply, diff, cumulative diff...)
    async fn delete_block_at_topoheight(&mut self, topoheight: u64) -> Result<(Hash, Arc<BlockHeader>, Vec<(Hash, Arc<Transaction>)>), BlockchainError>;

    // delete versioned balances at topoheight
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete versioned nonces at topoheight
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete versioned balances above topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete versioned nonces above topoheight
    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete account registrations above topoheight
    async fn delete_registrations_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete account registrations below topoheight
    async fn delete_registrations_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete versioned balances below topoheight
    async fn delete_versioned_balances_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete versioned nonces below topoheight
    async fn delete_versioned_nonces_below_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete all versions of balances under the specified topoheight
    // for those who don't have more recents, set it to the topoheight
    // for those above it, cut the chain by deleting the previous topoheight when it's going under
    async fn create_snapshot_balances_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // same as above but for nonces
    async fn create_snapshot_nonces_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // same as above but for registrations
    async fn create_snapshot_registrations_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // Get the network on which the chain is running
    fn get_network(&self) -> Result<Network, BlockchainError>;

    // Verify if we already marked this chain as having a network
    fn has_network(&self) -> Result<bool, BlockchainError>;

    // Set the network on which the chain is running
    fn set_network(&mut self, network: &Network) -> Result<(), BlockchainError>;

    // Count is the number of blocks (topoheight) to rewind
    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: u64, count: u64, stable_height: u64) -> Result<(u64, u64, Vec<(Hash, Arc<Transaction>)>), BlockchainError>;

    // Get the top block hash of the chain
    async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError>;
    
    // Get the top block of the chain, based on top block hash
    async fn get_top_block(&self) -> Result<Block, BlockchainError>;

    // Get the top block header of the chain, based on top block hash
    async fn get_top_block_header(&self) -> Result<(Arc<BlockHeader>, Hash), BlockchainError>;

    // Get the top topoheight of the chain
    fn get_top_topoheight(&self) -> Result<u64, BlockchainError>;

    // Set the top topoheight of the chain
    fn set_top_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // Get the top height of the chain
    fn get_top_height(&self) -> Result<u64, BlockchainError>;

    // Set the top height of the chain
    fn set_top_height(&mut self, height: u64) -> Result<(), BlockchainError>;

    // Get current chain tips
    async fn get_tips(&self) -> Result<Tips, BlockchainError>;

    // Store chain tips
    fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError>;

    // Get the size of the chain on disk in bytes
    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError>;

    // Stop the storage and wait for it to finish
    async fn stop(&mut self) -> Result<(), BlockchainError>;
}