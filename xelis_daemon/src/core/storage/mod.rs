mod providers;
mod cache;

pub mod sled;
pub mod rocksdb;

pub use self::{
    providers::*,
    sled::SledStorage,
    rocksdb::RocksStorage,
};

use std::collections::HashSet;
use async_trait::async_trait;
use xelis_common::{
    block::{
        BlockHeader,
        TopoHeight,
    },
    contract::ContractProvider as ContractInfoProvider,
    crypto::Hash,
    immutable::Immutable,
    transaction::Transaction
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
    + ContractInfoProvider + ContractBalanceProvider + VersionedProvider + SupplyProvider
    + CacheProvider + StateProvider
    + Sync + Send + 'static {
    // delete block at topoheight, and all pointers (hash_at_topo, topo_by_hash, reward, supply, diff, cumulative diff...)
    async fn delete_block_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(Hash, Immutable<BlockHeader>, Vec<(Hash, Immutable<Transaction>)>), BlockchainError>;

    // Count is the number of blocks (topoheight) to rewind
    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: TopoHeight, count: u64, stable_height: u64) -> Result<(u64, TopoHeight, Vec<(Hash, Immutable<Transaction>)>), BlockchainError>;

    // Get the size of the chain on disk in bytes
    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError>;

    // Estimate the size of the DB in bytes
    async fn estimate_size(&self) -> Result<u64, BlockchainError>;

    // Stop the storage and wait for it to finish
    async fn stop(&mut self) -> Result<(), BlockchainError>;

    // Flush the inner DB after a block being written
    async fn flush(&mut self) -> Result<(), BlockchainError>;
}