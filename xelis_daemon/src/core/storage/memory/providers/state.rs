use async_trait::async_trait;
use xelis_common::{
    block::{Block, BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable,
};
use crate::core::{
    error::BlockchainError,
    storage::{
        StateProvider,
        DagOrderProvider,
        DifficultyProvider,
        BlockProvider,
    },
};
use super::super::MemoryStorage;

#[async_trait]
impl StateProvider for MemoryStorage {
    async fn get_top_block_hash(&self) -> Result<Hash, BlockchainError> {
        self.get_hash_at_topo_height(self.cache.topoheight).await
    }

    async fn get_top_block(&self) -> Result<Block, BlockchainError> {
        let hash = self.get_top_block_hash().await?;
        self.get_block_by_hash(&hash).await
    }

    async fn get_top_block_header(&self) -> Result<(Immutable<BlockHeader>, Hash), BlockchainError> {
        let hash = self.get_top_block_hash().await?;
        let header = self.get_block_header_by_hash(&hash).await?;
        Ok((header, hash))
    }

    async fn get_top_topoheight(&self) -> Result<TopoHeight, BlockchainError> {
        Ok(self.cache.topoheight)
    }

    async fn set_top_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        self.cache.topoheight = topoheight;
        Ok(())
    }

    async fn get_top_height(&self) -> Result<u64, BlockchainError> {
        Ok(self.cache.height)
    }

    async fn set_top_height(&mut self, height: u64) -> Result<(), BlockchainError> {
        self.cache.height = height;
        Ok(())
    }
}
