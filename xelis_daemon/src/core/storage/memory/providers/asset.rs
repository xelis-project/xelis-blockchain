use anyhow::Context;
use itertools::Either;
use pooled_arc::PooledArc;
use async_trait::async_trait;
use xelis_common::{
    asset::{AssetData, VersionedAssetData},
    block::TopoHeight,
    crypto::{Hash, PublicKey},
};
use crate::core::{
    error::BlockchainError,
    storage::AssetProvider,
};
use super::super::MemoryStorage;

#[async_trait]
impl AssetProvider for MemoryStorage {
    async fn has_asset(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.assets.contains_key(hash))
    }

    async fn has_asset_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        self.assets.get(hash)
            .map(|a| a.data.contains_key(&topoheight))
            .with_context(|| format!("Asset {} not found", hash))
            .map_err(|e| e.into())
    }

    async fn get_asset_topoheight(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.assets.get(hash).and_then(|a| a.data.keys().next_back()).copied())
    }

    async fn get_asset_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedAssetData, BlockchainError> {
        self.assets.get(hash)
            .and_then(|a| a.data.get(&topoheight))
            .cloned()
            .ok_or(BlockchainError::AssetNotFound(hash.clone()))
    }

    async fn is_asset_registered_at_maximum_topoheight(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        match self.get_asset_topoheight(hash).await? {
            Some(topo) if topo <= maximum_topoheight => Ok(true),
            _ => Ok(false),
        }
    }

    async fn get_asset_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedAssetData)>, BlockchainError> {
        Ok(self.assets.get(hash)
            .and_then(|a| a.data.range(..=topoheight).next_back())
            .map(|(t, d)| (*t, d.clone())))
    }

    async fn get_asset(&self, hash: &Hash) -> Result<(TopoHeight, VersionedAssetData), BlockchainError> {
        self.assets.get(hash)
            .and_then(|a| a.data.iter().next_back())
            .map(|(t, d)| (*t, d.clone()))
            .ok_or(BlockchainError::AssetNotFound(hash.clone()))
    }

    async fn get_assets<'a>(&'a self) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        Ok(self.assets.keys().map(|k| Ok(k.as_ref().clone())))
    }

    async fn get_assets_with_data_in_range<'a>(&'a self, minimum_topoheight: Option<u64>, maximum_topoheight: Option<u64>) -> Result<impl Iterator<Item = Result<(Hash, TopoHeight, AssetData), BlockchainError>> + 'a, BlockchainError> {
        Ok(self.assets.iter().flat_map(move |(hash, entry)| {
            match (minimum_topoheight, maximum_topoheight) {
                (Some(min), Some(max)) => Either::Left(entry.data.range(min..=max)),
                (Some(min), None) => Either::Left(entry.data.range(min..)),
                (None, Some(max)) => Either::Left(entry.data.range(..=max)),
                (None, None) => Either::Right(entry.data.iter()),
            }.map(move |(topo, data)| Ok((hash.as_ref().clone(), *topo, data.clone().take())))
        }))
    }

    async fn get_assets_for<'a>(&'a self, key: &'a PublicKey) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        Ok(self.accounts.get(&PooledArc::from_ref(key))
            .into_iter()
            .flat_map(|acc| acc.balances.keys())
            .map(|asset| Ok(asset.as_ref().clone()))
        )
    }

    async fn count_assets(&self) -> Result<u64, BlockchainError> {
        Ok(self.assets.len() as u64)
    }

    async fn add_asset(&mut self, hash: &Hash, topoheight: TopoHeight, data: VersionedAssetData) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(hash);
        self.assets.entry(shared)
            .or_default()
            .data
            .insert(topoheight, data);

        Ok(())
    }
}
