use async_trait::async_trait;
use xelis_common::{
    block::{BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable
};
use crate::core::error::BlockchainError;
use super::{BlockProvider, DagOrderProvider};

#[async_trait]
pub trait BlockDagProvider: DagOrderProvider + BlockProvider {
    // Get a block header & hash from its topoheight
    async fn get_block_header_at_topoheight(&self, topoheight: TopoHeight) -> Result<(Hash, Immutable<BlockHeader>), BlockchainError>;

    // Get the block reward from using topoheight
    async fn get_block_reward_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError>;

    // Get the supply from topoheight
    async fn get_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError>;

    // Get the burned supply from topoheight
    async fn get_burned_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError>;

    // Set the metadata for topoheight
    async fn set_topoheight_metadata(&mut self, topoheight: TopoHeight, block_reward: u64, supply: u64, burned_supply: u64) -> Result<(), BlockchainError>;
}