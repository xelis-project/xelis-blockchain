use std::sync::Arc;

use async_trait::async_trait;
use xelis_common::{
    block::{TopoHeight, BlockHeader},
    crypto::Hash
};
use crate::core::error::BlockchainError;
use super::{BlockProvider, DagOrderProvider};

#[async_trait]
pub trait BlockDagProvider: DagOrderProvider + BlockProvider {
    // Get a block header & hash from its topoheight
    async fn get_block_header_at_topoheight(&self, topoheight: TopoHeight) -> Result<(Hash, Arc<BlockHeader>), BlockchainError>;

    // Get the block reward from using topoheight
    fn get_block_reward_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError>;

    // Get the supply from topoheight
    async fn get_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError>;

    // Get the burned supply from topoheight
    async fn get_burned_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError>;

    // Set the block reward for topoheight
    fn set_block_reward_at_topo_height(&mut self, topoheight: TopoHeight, reward: u64) -> Result<(), BlockchainError>;

    // Set the supply at topoheight
    fn set_supply_at_topo_height(&mut self, topoheight: TopoHeight, supply: u64) -> Result<(), BlockchainError>;

    // Set the burned supply at topoheight
    fn set_burned_supply_at_topo_height(&mut self, topoheight: TopoHeight, burned_supply: u64) -> Result<(), BlockchainError>;
}