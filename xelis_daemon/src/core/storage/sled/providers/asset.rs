use async_trait::async_trait;
use log::trace;
use xelis_common::{
    asset::{AssetData, VersionedAssetData},
    block::TopoHeight,
    crypto::{elgamal::RISTRETTO_COMPRESSED_SIZE, Hash, PublicKey},
    serializer::{Serializer, Skip}
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::{AssetProvider, SledStorage},
};

#[async_trait]
impl AssetProvider for SledStorage {
    async fn has_asset(&self, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("asset exist {}", asset);
        self.contains_data_cached(&self.assets, self.cache.objects.as_ref().map(|o| &o.assets_cache), asset).await
    }

    async fn has_asset_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has asset {} at exact topoheight {}", asset, topoheight);

        if !self.has_asset(asset).await? {
            return Ok(false)
        }

        let key = Self::get_asset_key(asset, topoheight);
        self.contains_data(&self.versioned_assets, &key)
    }

    async fn is_asset_registered_at_maximum_topoheight(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("is asset {} registered at maximum topoheight {}", hash, maximum_topoheight);
        let topoheight = self.get_asset_topoheight(hash).await?;
        match topoheight {
            Some(topo) if topo <= maximum_topoheight => Ok(true),
            _ => Ok(false)
        }
    }

    async fn get_asset_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedAssetData)>, BlockchainError> {
        trace!("get asset {} at maximum topoheight {}", hash, topoheight);
        let mut topo = if self.has_asset_at_exact_topoheight(hash, topoheight).await? {
            Some(topoheight)
        } else {
            self.get_asset_topoheight(hash).await?
        };

        while let Some(previous) = topo {
            if previous <= topoheight {
                let data = self.get_asset_at_topoheight(hash, previous).await?;
                return Ok(Some((previous, data)))
            }

            topo = self.load_from_disk(&self.versioned_assets, &Self::get_asset_key(hash, previous), DiskContext::AssetAtTopoHeight(previous))?;
        }

        Ok(None)
    }

    async fn get_asset(&self, hash: &Hash) -> Result<(TopoHeight, VersionedAssetData), BlockchainError> {
        trace!("get asset {}", hash);
        let topoheight = self.get_asset_topoheight(hash).await?;
        match topoheight {
            Some(topoheight) => {
                let data = self.get_asset_at_topoheight(hash, topoheight).await?;
                Ok((topoheight, data))
            },
            None => Err(BlockchainError::AssetNotFound(hash.clone())),
        }
    }

    async fn get_asset_topoheight(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get asset topoheight {}", hash);
        self.get_optional_cacheable_data(&self.assets, self.cache.objects.as_ref().map(|o| &o.assets_cache), hash).await
    }

    async fn get_asset_at_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedAssetData, BlockchainError> {
        trace!("get asset registration topoheight {}", asset);
        let key = Self::get_asset_key(asset, topoheight);
        self.load_from_disk(&self.versioned_assets, &key, DiskContext::AssetAtTopoHeight(topoheight))
    }

    // we are forced to read from disk directly because cache may don't have all assets in memory
    async fn get_assets<'a>(&'a self) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("get assets");
        Ok(Self::iter_keys::<Hash>(self.snapshot.as_ref(), &self.assets))
    }

    async fn get_assets_with_data_in_range<'a>(&'a self, minimum_topoheight: Option<u64>, maximum_topoheight: Option<u64>) -> Result<impl Iterator<Item = Result<(Hash, TopoHeight, AssetData), BlockchainError>> + 'a, BlockchainError> {
        Ok(Self::iter::<Hash, TopoHeight>(self.snapshot.as_ref(), &self.assets)
            .map(move |res| {
                let (asset, topoheight) = res?;
                if minimum_topoheight.is_some_and(|v| topoheight < v) || maximum_topoheight.is_some_and(|v| topoheight > v) {
                    return Ok(None)
                }

                let key = Self::get_asset_key(&asset, topoheight);
                let data: VersionedAssetData = self.load_from_disk(&self.versioned_assets, &key, DiskContext::AssetAtTopoHeight(topoheight))?;

                Ok(Some((asset, topoheight, data.take())))
            })
            .filter_map(Result::transpose)
        )
    }

    // Returns all assets that the key has
    async fn get_assets_for<'a>(&'a self, key: &'a PublicKey) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        Ok(Self::scan_prefix_keys::<Skip<RISTRETTO_COMPRESSED_SIZE, Hash>>(self.snapshot.as_ref(), &self.balances, key.as_bytes()).map(|res| {
            let key = res?;
            // Keys are stored like this: [public key (32 bytes)][asset hash (32 bytes)]
            // See Self::get_balance_key_for
            Ok(key.0)
        }))
    }

    // count assets in storage
    async fn count_assets(&self) -> Result<u64, BlockchainError> {
        trace!("count assets");
        Ok(self.cache().assets_count)
    }

    async fn add_asset(&mut self, asset: &Hash, topoheight: TopoHeight, data: VersionedAssetData) -> Result<(), BlockchainError> {
        trace!("add asset {} at topoheight {}", asset, topoheight);

        if !self.contains_data(&self.assets, asset.as_bytes())? {
            self.store_assets_count(self.count_assets().await? + 1)?;
        }

        Self::insert_into_disk(self.snapshot.as_mut(), &self.assets, asset.as_bytes(), &topoheight.to_be_bytes())?;

        let key = Self::get_asset_key(asset, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_assets, &key, data.to_bytes())?;

        if let Some(cache) = self.cache.objects.as_mut().map(|o| o.assets_cache.get_mut()) {
            cache.put(asset.clone(), topoheight);
        }
        Ok(())
    }
}

impl SledStorage {
    pub fn get_asset_key(asset: &Hash, topoheight: TopoHeight) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[0..8].copy_from_slice(&topoheight.to_be_bytes());
        key[8..].copy_from_slice(asset.as_bytes());
        key
    }
}