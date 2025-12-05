use async_trait::async_trait;
use xelis_common::{
    block::{BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable
};
use crate::core::{error::BlockchainError, storage::types::TopoHeightMetadata};
use super::{BlockProvider, DagOrderProvider};

#[async_trait]
pub trait BlockDagProvider: DagOrderProvider + BlockProvider {
    // Get a block header & hash from its topoheight
    async fn get_block_header_at_topoheight(&self, topoheight: TopoHeight) -> Result<(Hash, Immutable<BlockHeader>), BlockchainError>;

    // Get the block reward from using topoheight
    async fn get_block_reward_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError>;

    // Get the supply from topoheight
    async fn get_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError>;

    // Set the metadata for topoheight
    async fn get_metadata_at_topoheight(&self, topoheight: TopoHeight) -> Result<TopoHeightMetadata, BlockchainError>;

    // Set the metadata for topoheight
    async fn set_metadata_at_topoheight(&mut self, topoheight: TopoHeight, metadata: TopoHeightMetadata) -> Result<(), BlockchainError>;
}