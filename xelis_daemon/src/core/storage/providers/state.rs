use async_trait::async_trait;
use xelis_common::{
    block::{Block, BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable
};

use crate::core::error::BlockchainError;

#[async_trait]
pub trait StateProvider {
    // Get the top block hash of the chain
    async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError>;
    
    // Get the top block of the chain, based on top block hash
    async fn get_top_block(&self) -> Result<Block, BlockchainError>;

    // Get the top block header of the chain, based on top block hash
    async fn get_top_block_header(&self) -> Result<(Immutable<BlockHeader>, Hash), BlockchainError>;

    // Get the top topoheight of the chain
    async fn get_top_topoheight(&self) -> Result<TopoHeight, BlockchainError>;

    // Set the top topoheight of the chain
    async fn set_top_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Get the top height of the chain
    async fn get_top_height(&self) -> Result<u64, BlockchainError>;

    // Set the top height of the chain
    async fn set_top_height(&mut self, height: u64) -> Result<(), BlockchainError>;
}