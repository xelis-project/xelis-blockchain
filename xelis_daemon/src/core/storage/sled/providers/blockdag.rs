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

    fn get_block_reward_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get block reward at topo height {}", topoheight);
        Ok(self.load_from_disk(&self.rewards, &topoheight.to_be_bytes(), DiskContext::BlockRewardAtTopoHeight(topoheight))?)
    }

    async fn get_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get supply at topo height {}", topoheight);
        self.load_from_disk(&self.supply, &topoheight.to_be_bytes(), DiskContext::SupplyAtTopoHeight(topoheight))
    }

    async fn get_burned_supply_at_topo_height(&self, topoheight: TopoHeight) -> Result<u64, BlockchainError> {
        trace!("get burned supply at topo height {}", topoheight);
        self.load_from_disk(&self.burned_supply, &topoheight.to_be_bytes(), DiskContext::BurnedSupplyAtTopoHeight(topoheight))
    }

    fn set_block_reward_at_topo_height(&mut self, topoheight: TopoHeight, reward: u64) -> Result<(), BlockchainError> {
        trace!("set block reward to {} at topo height {}", reward, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.rewards, &topoheight.to_be_bytes(), &reward.to_be_bytes())?;
        Ok(())
    }

    fn set_supply_at_topo_height(&mut self, topoheight: TopoHeight, supply: u64) -> Result<(), BlockchainError> {
        trace!("set supply at topo height {}", topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.supply, &topoheight.to_be_bytes(), &supply.to_be_bytes())?;
        Ok(())
    }

    fn set_burned_supply_at_topo_height(&mut self, topoheight: TopoHeight, burned_supply: u64) -> Result<(), BlockchainError> {
        trace!("set burned supply at topo height {}", topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.burned_supply, &topoheight.to_be_bytes(), &burned_supply.to_be_bytes())?;
        Ok(())
    }
}