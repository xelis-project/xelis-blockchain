use async_trait::async_trait;
use log::trace;
use xelis_common::{
    block::{BlockHeader, TopoHeight},
    crypto::Hash,
    immutable::Immutable
};

use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{
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
        Ok(self.load_from_disk(&self.rewards, &topoheight.to_be_bytes(), DiskContext::BlockRewardAtTopoHeight(topoheight))?)
    }

    async fn get_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get supply at topo height {}", topoheight);
        self.load_from_disk(&self.supply, &topoheight.to_be_bytes(), DiskContext::SupplyAtTopoHeight(topoheight))
    }

    // Set the metadata for topoheight
    async fn set_topoheight_metadata(&mut self, topoheight: TopoHeight, block_reward: u64, supply: u64) -> Result<(), BlockchainError> {
        trace!("set topoheight metadata at {}", topoheight);

        Self::insert_into_disk(self.snapshot.as_mut(), &self.rewards, &topoheight.to_be_bytes(), &block_reward.to_be_bytes())?;
        Self::insert_into_disk(self.snapshot.as_mut(), &self.supply, &topoheight.to_be_bytes(), &supply.to_be_bytes())?;

        Ok(())
    }
}