use pooled_arc::PooledArc;
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::{
    error::BlockchainError,
    storage::{AssetCirculatingSupplyProvider, VersionedSupply},
};
use super::super::MemoryStorage;

#[async_trait]
impl AssetCirculatingSupplyProvider for MemoryStorage {
    async fn has_circulating_supply_for_asset(&self, asset: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.assets.get(asset).map_or(false, |a| !a.supply.is_empty()))
    }

    async fn has_circulating_supply_for_asset_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.assets.get(asset)
            .map_or(false, |a| a.supply.contains_key(&topoheight))
        )
    }

    async fn get_circulating_supply_for_asset_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedSupply, BlockchainError> {
        self.assets.get(asset)
            .and_then(|a| a.supply.get(&topoheight))
            .cloned()
            .ok_or(BlockchainError::AssetNotFound(asset.clone()))
    }

    async fn get_circulating_supply_for_asset_at_maximum_topoheight(&self, asset: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError> {
        Ok(self.assets.get(asset)
            .and_then(|a| a.supply.range(..=maximum_topoheight).next_back())
            .map(|(t, s)| (*t, s.clone())))
    }

    async fn set_last_circulating_supply_for_asset(&mut self, hash: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(hash);
        self.assets.entry(shared)
            .or_default()
            .supply
            .insert(topoheight, supply.clone());
        Ok(())
    }
}
