use std::sync::Arc;

use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::BlockHeader,
    crypto::Hash
};

use crate::core::{error::BlockchainError, storage::SledStorage};

use super::{BlockProvider, DagOrderProvider, DifficultyProvider};

#[async_trait]
pub trait BlockDagProvider: DagOrderProvider + BlockProvider {
    // Get a block header & hash from its topoheight
    async fn get_block_header_at_topoheight(&self, topoheight: u64) -> Result<(Hash, Arc<BlockHeader>), BlockchainError>;

    // Get the block reward from using topoheight
    fn get_block_reward_at_topo_height(&self, topoheight: u64) -> Result<u64, BlockchainError>;

    // Get the supply from topoheight
    async fn get_supply_at_topo_height(&self, topoheight: u64) -> Result<u64, BlockchainError>;

    // Set the block reward for topoheight
    fn set_block_reward_at_topo_height(&mut self, topoheight: u64, reward: u64) -> Result<(), BlockchainError>;

    // Set the supply at topoheight
    fn set_supply_at_topo_height(&mut self, topoheight: u64, supply: u64) -> Result<(), BlockchainError>;
}

#[async_trait]
impl BlockDagProvider for SledStorage {
    async fn get_block_header_at_topoheight(&self, topoheight: u64) -> Result<(Hash, Arc<BlockHeader>), BlockchainError> {
        trace!("get block at topoheight: {}", topoheight);
        let hash = self.get_hash_at_topo_height(topoheight).await?;
        let block = self.get_block_header_by_hash(&hash).await?;
        Ok((hash, block))
    }

    fn get_block_reward_at_topo_height(&self, topoheight: u64) -> Result<u64, BlockchainError> {
        trace!("get block reward at topo height {}", topoheight);
        Ok(self.load_from_disk(&self.rewards, &topoheight.to_be_bytes())?)
    }

    async fn get_supply_at_topo_height(&self, topoheight: u64) -> Result<u64, BlockchainError> {
        trace!("get supply at topo height {}", topoheight);
        self.load_from_disk(&self.supply, &topoheight.to_be_bytes())
    }

    fn set_block_reward_at_topo_height(&mut self, topoheight: u64, reward: u64) -> Result<(), BlockchainError> {
        trace!("set block reward to {} at topo height {}", reward, topoheight);
        self.rewards.insert(topoheight.to_be_bytes(), &reward.to_be_bytes())?;
        Ok(())
    }

    fn set_supply_at_topo_height(&mut self, topoheight: u64, supply: u64) -> Result<(), BlockchainError> {
        trace!("set supply at topo height {}", topoheight);
        self.supply.insert(topoheight.to_be_bytes(), &supply.to_be_bytes())?;
        Ok(())
    }
}