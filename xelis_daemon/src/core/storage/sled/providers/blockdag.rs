use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::{BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable,
    serializer::Serializer
};

use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
        types::TopoHeightMetadata,
        BlockDagProvider,
        DagOrderProvider,
        DifficultyProvider,
        SledStorage
    }
};

#[async_trait]
impl BlockDagProvider for SledStorage {
    async fn get_block_header_at_topoheight(&self, topoheight: TopoHeight) -> Result<(Hash, Immutable<BlockHeader>), BlockchainError> {
        trace!("get block at topoheight: {}", topoheight);
        let hash = self.get_hash_at_topo_height(topoheight).await?;
        let block = self.get_block_header_by_hash(&hash).await?;
        Ok((hash, block))
    }

    async fn get_block_reward_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get block reward at topo height {}", topoheight);
        self.get_metadata_at_topoheight(topoheight).await
            .map(|metadata| metadata.block_reward)
    }

    async fn get_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get supply at topo height {}", topoheight);
        self.get_metadata_at_topoheight(topoheight).await
            .map(|metadata| metadata.emitted_supply)
    }

    async fn get_metadata_at_topoheight(&self, topoheight: TopoHeight) -> Result<TopoHeightMetadata, BlockchainError> {
        trace!("get metadata at topoheight {}", topoheight);
        // TODO: maybe use a cache
        self.load_from_disk(&self.topoheight_metadata, &topoheight.to_be_bytes(), DiskContext::MetadataAtTopoHeight(topoheight))
    }

    // Set the metadata for topoheight
    async fn set_metadata_at_topoheight(&mut self, topoheight: TopoHeight, metadata: TopoHeightMetadata) -> Result<(), BlockchainError> {
        trace!("set topoheight metadata at {}", topoheight);

        Self::insert_into_disk(self.snapshot.as_mut(), &self.topoheight_metadata, &topoheight.to_be_bytes(), metadata.to_bytes())?;

        Ok(())
    }
}