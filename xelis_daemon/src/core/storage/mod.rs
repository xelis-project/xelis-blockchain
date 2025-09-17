mod providers;
mod cache;

pub mod types;
pub mod sled;

#[cfg(feature = "rocksdb")]
pub mod rocksdb;

pub use self::{
    providers::*,
    sled::SledStorage,
    
};

#[cfg(feature = "rocksdb")]
pub use rocksdb::RocksStorage;

use std::collections::HashSet;
use async_trait::async_trait;
use log::{debug, trace, warn};
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
use crate::{config::PRUNE_SAFETY_LIMIT, core::error::BlockchainError};

// Represents the tips of the chain or of a block
pub type Tips = HashSet<Hash>;

#[async_trait]
pub trait Storage:
    BlockExecutionOrderProvider + DagOrderProvider + PrunedTopoheightProvider
    + NonceProvider + AccountProvider + ClientProtocolProvider + BlockDagProvider
    + MerkleHashProvider + NetworkProvider + MultiSigProvider + TipsProvider
    + CommitPointProvider + ContractProvider + ContractDataProvider + ContractOutputsProvider
    + ContractInfoProvider + ContractBalanceProvider + VersionedProvider + AssetCirculatingSupplyProvider
    + CacheProvider + StateProvider
    + Sync + Send + 'static {
    // delete block at topoheight, and all pointers (hash_at_topo, topo_by_hash, reward, supply, diff, cumulative diff...)
    async fn delete_block_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(Hash, Immutable<BlockHeader>, Vec<(Hash, Immutable<Transaction>)>), BlockchainError>;

    // Count is the number of blocks (topoheight) to rewind
    async fn pop_blocks(&mut self, mut height: u64, mut topoheight: TopoHeight, count: u64, until_topo_height: TopoHeight) -> Result<(u64, TopoHeight, Vec<(Hash, Immutable<Transaction>)>), BlockchainError> {
        trace!("pop blocks from height: {}, topoheight: {}, count: {}", height, topoheight, count);
        if topoheight < count as u64 { // also prevent removing genesis block
            return Err(BlockchainError::NotEnoughBlocks);
        }

        let start_topoheight = topoheight;
        // search the lowest topo height available based on count + 1
        // (last lowest topo height accepted)
        let mut lowest_topo = topoheight - count;
        trace!("Lowest topoheight for rewind: {}", lowest_topo);

        let pruned_topoheight = self.get_pruned_topoheight().await?.unwrap_or(0);

        // we must check that we are stopping a sync block
        // easy way for this: check the block at topo is currently alone at height
        while lowest_topo > pruned_topoheight {
            let hash = self.get_hash_at_topo_height(lowest_topo).await?;
            let block_height = self.get_height_for_block_hash(&hash).await?;
            let blocks_at_height = self.get_blocks_at_height(block_height).await?;
            if blocks_at_height.len() == 1 {
                debug!("Sync block found at topoheight {}", lowest_topo);
                break;
            } else {
                warn!("No sync block found at topoheight {} we must go lower if possible", lowest_topo);
                lowest_topo -= 1;
            }
        }

        if pruned_topoheight != 0 {
            let safety_pruned_topoheight = pruned_topoheight + PRUNE_SAFETY_LIMIT;
            if lowest_topo <= safety_pruned_topoheight && until_topo_height != 0 {
                warn!("Pruned topoheight is {}, lowest topoheight is {}, rewind only until {}", pruned_topoheight, lowest_topo, safety_pruned_topoheight);
                lowest_topo = safety_pruned_topoheight;
            }
        }

        // new TIPS for chain
        let mut tips = self.get_tips().await?;

        // Delete all orphaned blocks tips
        for tip in tips.clone() {
            if !self.is_block_topological_ordered(&tip).await? {
                debug!("Tip {} is not ordered, removing", tip);
                tips.remove(&tip);
            }
        }

        // all txs to be rewinded
        let mut txs = Vec::new();
        let mut done = 0;
        'main: loop {
            // stop rewinding if its genesis block or if we reached the lowest topo
            if topoheight <= lowest_topo || topoheight <= until_topo_height || topoheight == 0 { // prevent removing genesis block
                trace!("Done: {done}, count: {count}, height: {height}, topoheight: {topoheight}, lowest topo: {lowest_topo}, stable topo: {until_topo_height}");
                break 'main;
            }

            // Delete the hash at topoheight
            let (hash, block, block_txs) = self.delete_block_at_topoheight(topoheight).await?;
            self.delete_versioned_data_at_topoheight(topoheight).await?;

            debug!("Block {} at topoheight {} deleted", hash, topoheight);
            txs.extend(block_txs);

            // generate new tips
            trace!("Removing {} from {} tips", hash, tips.len());
            tips.remove(&hash);
 
            for hash in block.get_tips().iter() {
                trace!("Adding {} to {} tips", hash, tips.len());
                tips.insert(hash.clone());
            }

            if topoheight <= pruned_topoheight {
                warn!("Pruned topoheight is reached, this is not healthy, starting from 0");
                topoheight = 0;
                height = 0;

                // Remove total blocks
                done = start_topoheight;

                tips.clear();
                tips.insert(self.get_hash_at_topo_height(0).await?);

                self.set_pruned_topoheight(None).await?;

                // Clear out ALL data
                self.delete_versioned_data_above_topoheight(0).await?;

                break 'main;
            }

            topoheight -= 1;
            // height of old block become new height
            if block.get_height() < height {
                height = block.get_height();
            }
            done += 1;
        }

        warn!("Blocks rewinded: {}, new topoheight: {}, new height: {}", done, topoheight, height);

        trace!("Cleaning caches");
        // Clear all caches to not have old data after rewind
        self.clear_caches().await?;

        trace!("Storing new pointers");
        // store the new tips and topo topoheight
        self.store_tips(&tips).await?;
        self.set_top_topoheight(topoheight).await?;
        self.set_top_height(height).await?;

        // Reduce the count of blocks stored
        self.decrease_blocks_count(done).await?;

        Ok((height, topoheight, txs))
    }

    // Get the size of the chain on disk in bytes
    async fn get_size_on_disk(&self) -> Result<u64, BlockchainError>;

    // Estimate the size of the DB in bytes
    async fn estimate_size(&self) -> Result<u64, BlockchainError>;

    // Stop the storage and wait for it to finish
    async fn stop(&mut self) -> Result<(), BlockchainError>;

    // Flush the inner DB after a block being written
    async fn flush(&mut self) -> Result<(), BlockchainError>;
}