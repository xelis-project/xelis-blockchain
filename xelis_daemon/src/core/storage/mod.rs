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
    crypto::hash::Hash,
    network::Network,
    transaction::Transaction,
};
use crate::core::error::BlockchainError;
pub type Tips = HashSet<Hash>;

#[async_trait]
pub trait Storage: DagOrderProvider + PrunedTopoheightProvider + NonceProvider + ClientProtocolProvider + BlockProvider + Sync + Send + 'static {
    // Clear caches if exists
    async fn clear_caches(&mut self) -> Result<(), BlockchainError>;

    // delete block at topoheight, and all pointers (hash_at_topo, topo_by_hash, reward, supply, diff, cumulative diff...)
    async fn delete_block_at_topoheight(&mut self, topoheight: u64) -> Result<(Hash, Arc<BlockHeader>, Vec<(Hash, Arc<Transaction>)>), BlockchainError>;

    // delete versioned balances at topoheight
    async fn delete_versioned_balances_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete versioned nonces at topoheight
    async fn delete_versioned_nonces_at_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete versioned balances above or at topoheight
    async fn delete_versioned_balances_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    // delete versioned nonces above or at topoheight
    async fn delete_versioned_nonces_above_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

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

    fn get_network(&self) -> Result<Network, BlockchainError>;

    fn has_network(&self) -> Result<bool, BlockchainError>;

    fn set_network(&mut self, network: &Network) -> Result<(), BlockchainError>;

    fn get_block_reward_at_topo_height(&self, topoheight: u64) -> Result<u64, BlockchainError>;

    fn set_block_reward_at_topo_height(&mut self, topoheight: u64, reward: u64) -> Result<(), BlockchainError>;

    // Count is the number of blocks (topoheight) to rewind
    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: u64, count: u64, stable_height: u64) -> Result<(u64, u64, Vec<(Hash, Arc<Transaction>)>), BlockchainError>;

    async fn get_block_header_at_topoheight(&self, topoheight: u64) -> Result<(Hash, Arc<BlockHeader>), BlockchainError>;

    async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError>;
    
    async fn get_top_block(&self) -> Result<Block, BlockchainError>;

    async fn get_top_block_header(&self) -> Result<(Arc<BlockHeader>, Hash), BlockchainError>;

    async fn get_supply_at_topo_height(&self, topoheight: u64) -> Result<u64, BlockchainError>;

    fn set_supply_at_topo_height(&mut self, topoheight: u64, supply: u64) -> Result<(), BlockchainError>;

    fn get_top_topoheight(&self) -> Result<u64, BlockchainError>;

    fn set_top_topoheight(&mut self, topoheight: u64) -> Result<(), BlockchainError>;

    fn get_top_height(&self) -> Result<u64, BlockchainError>;

    fn set_top_height(&mut self, height: u64) -> Result<(), BlockchainError>;

    async fn get_tips(&self) -> Result<Tips, BlockchainError>;

    fn store_tips(&mut self, tips: &Tips) -> Result<(), BlockchainError>;

    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError>;

    async fn stop(&mut self) -> Result<(), BlockchainError>;
}