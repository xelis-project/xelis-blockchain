mod providers;
mod sled;

pub use self::{
    sled::*,
    providers::*
};

use std::{collections::HashSet, sync::Arc};
use async_trait::async_trait;
use indexmap::IndexSet;
use xelis_common::{
    block::{
        Block,
        BlockHeader,
        TopoHeight,
    },
    contract::ContractProvider as ContractInfoProvider,
    crypto::Hash,
    transaction::Transaction,
};
use crate::core::error::BlockchainError;

// Represents the tips of the chain or of a block
pub type Tips = HashSet<Hash>;

#[async_trait]
pub trait Storage:
    BlockExecutionOrderProvider + DagOrderProvider + PrunedTopoheightProvider
    + NonceProvider + AccountProvider + ClientProtocolProvider + BlockDagProvider
    + MerkleHashProvider + NetworkProvider + MultiSigProvider + TipsProvider
    + CommitPointProvider + ContractProvider + ContractDataProvider + ContractOutputsProvider
    + ContractInfoProvider + ContractBalanceProvider + VersionedProvider + Sync + Send + 'static {
    // Clear caches if exists
    async fn clear_caches(&mut self) -> Result<(), BlockchainError>;

    // delete block at topoheight, and all pointers (hash_at_topo, topo_by_hash, reward, supply, diff, cumulative diff...)
    async fn delete_block_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(Hash, Arc<BlockHeader>, Vec<(Hash, Arc<Transaction>)>), BlockchainError>;

    // Count is the number of blocks (topoheight) to rewind
    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: TopoHeight, count: u64, stable_height: u64) -> Result<(u64, TopoHeight, Vec<(Hash, Arc<Transaction>)>), BlockchainError>;

    // Get the top block hash of the chain
    async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError>;
    
    // Get the top block of the chain, based on top block hash
    async fn get_top_block(&self) -> Result<Block, BlockchainError>;

    // Get the top block header of the chain, based on top block hash
    async fn get_top_block_header(&self) -> Result<(Arc<BlockHeader>, Hash), BlockchainError>;

    // Get the top topoheight of the chain
    fn get_top_topoheight(&self) -> Result<u64, BlockchainError>;

    // Set the top topoheight of the chain
    fn set_top_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Get the top height of the chain
    fn get_top_height(&self) -> Result<u64, BlockchainError>;

    // Set the top height of the chain
    fn set_top_height(&mut self, height: u64) -> Result<(), BlockchainError>;

    // Get the size of the chain on disk in bytes
    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError>;

    // Stop the storage and wait for it to finish
    async fn stop(&mut self) -> Result<(), BlockchainError>;

    // Get all the unexecuted transactions
    async fn get_unexecuted_transactions(&self) -> Result<IndexSet<Hash>, BlockchainError>;

    // Estimate the size of the DB in bytes
    async fn estimate_size(&self) -> Result<u64, BlockchainError>;
}