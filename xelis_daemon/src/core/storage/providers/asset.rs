use async_trait::async_trait;
use indexmap::{IndexMap, IndexSet};
use log::trace;
use xelis_common::{
    asset::AssetData,
    block::TopoHeight,
    crypto::{elgamal::RISTRETTO_COMPRESSED_SIZE, Hash, PublicKey},
    serializer::Serializer
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage,
};

#[async_trait]
pub trait AssetProvider {
    // Check if an asset exists
    async fn has_asset(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Check if asset is registered <= topoheight
    async fn has_asset_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the asset topoheight at which it got registered
    async fn get_asset_topoheight(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError>;

    // Get the asset data from its hash and topoheight at which it got registered
    async fn get_asset_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<AssetData, BlockchainError>;

    // Get the asset data from its hash and topoheight at which it got registered
    async fn get_asset(&self, hash: &Hash) -> Result<(TopoHeight, AssetData), BlockchainError>;

    // Get all available assets
    // TODO: replace with impl Iterator<Item = Result<Hash, BlockchainError>> when async trait methods are stable
    async fn get_assets(&self) -> Result<Vec<Hash>, BlockchainError>;

    // Get a partial list of assets supporting pagination and filtering by topoheight
    // TODO: replace with impl Iterator<Item = Result<Hash, BlockchainError>> when async trait methods are stable
    async fn get_partial_assets_with_topoheight(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexMap<Hash, (TopoHeight, AssetData)>, BlockchainError>;

    // Get a partial list of assets supporting pagination and filtering by topoheight
    // TODO: replace with impl Iterator<Item = Result<Hash, BlockchainError>> when async trait methods are stable
    async fn get_partial_assets(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexMap<Hash, AssetData>, BlockchainError>;

    // Get chunked assets
    // This is useful to not retrieve all assets at once
    async fn get_chunked_assets(&self, maximum: usize, skip: usize) -> Result<IndexSet<Hash>, BlockchainError>;

    // Get all assets for a specific key
    // TODO: replace with impl Iterator<Item = Result<Hash, BlockchainError>> when async trait methods are stable
    async fn get_assets_for(&self, key: &PublicKey) -> Result<Vec<Hash>, BlockchainError>;

    // Count the number of assets stored
    async fn count_assets(&self) -> Result<u64, BlockchainError>;

    // Add an asset to the storage
    async fn add_asset(&mut self, hash: &Hash, topoheight: TopoHeight, data: AssetData) -> Result<(), BlockchainError>;
}

#[async_trait]
impl AssetProvider for SledStorage {
    async fn has_asset(&self, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("asset exist {}", asset);
        self.contains_data_cached(&self.assets, &self.assets_cache, asset).await
    }

    async fn has_asset_at_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("asset exist at topoheight {}", asset);
        if !self.has_asset(asset).await? {
            return Ok(false);
        }

        let topo = self.get_asset_topoheight(asset).await?;
        Ok(topo <= topoheight)
    }

    async fn get_asset(&self, hash: &Hash) -> Result<(TopoHeight, AssetData), BlockchainError> {
        trace!("get asset {}", hash);
        let topoheight = self.get_asset_topoheight(hash).await?;
        Ok((topoheight, self.get_asset_at_topoheight(hash, topoheight).await?))
    }

    async fn get_asset_topoheight(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        trace!("get asset topoheight {}", hash);
        self.get_cacheable_data(&self.assets, &self.assets_cache, hash, DiskContext::Asset).await
    }

    async fn get_asset_at_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<AssetData, BlockchainError> {
        trace!("get asset registration topoheight {}", asset);
        let key = Self::get_asset_key(asset, topoheight);
        self.load_from_disk(&self.assets_prefixed, &key, DiskContext::Asset)
    }

    // we are forced to read from disk directly because cache may don't have all assets in memory
    async fn get_assets(&self) -> Result<Vec<Hash>, BlockchainError> {
        trace!("get assets");

        self.assets.iter().keys().map(|res| {
            let key = res?;
            Ok(Hash::from_bytes(&key)?)
        }).collect()
    }

    async fn get_partial_assets_with_topoheight(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexMap<Hash, (TopoHeight, AssetData)>, BlockchainError> {
        trace!("get partial assets with topoheight with maximum {} and skip {}", maximum, skip);
        let mut assets = IndexMap::new();
        let mut skip_count = 0;
        for el in self.assets.iter() {
            let (key, value) = el?;
            let topo = u64::from_bytes(&value)?;
            // check that we have a registered asset before the maximum topoheight
            if topo >= minimum_topoheight && topo <= maximum_topoheight {
                if skip_count < skip {
                    skip_count += 1;
                } else {
                    let asset = Hash::from_bytes(&key)?;

                    let data = self.get_asset_at_topoheight(&asset, topo).await?;
                    assets.insert(asset, (topo, data));

                    if assets.len() == maximum {
                        break;
                    }
                }
            }
        }
        Ok(assets)
    }

    async fn get_partial_assets(&self, maximum: usize, skip: usize, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<IndexMap<Hash, AssetData>, BlockchainError> {
        trace!("get partial assets with maximum {} and skip {}", maximum, skip);
        let mut assets = IndexMap::new();
        let mut skip_count = 0;
        for el in self.assets.iter() {
            let (key, value) = el?;
            let topo = u64::from_bytes(&value)?;
            // check that we have a registered asset before the maximum topoheight
            if topo >= minimum_topoheight && topo <= maximum_topoheight {
                if skip_count < skip {
                    skip_count += 1;
                } else {
                    let asset = Hash::from_bytes(&key)?;

                    let data = self.get_asset_at_topoheight(&asset, topo).await?;
                    assets.insert(asset, data);

                    if assets.len() == maximum {
                        break;
                    }
                }
            }
        }
        Ok(assets)
    }

    async fn get_chunked_assets(&self, maximum: usize, skip: usize) -> Result<IndexSet<Hash>, BlockchainError> {
        let mut assets = IndexSet::with_capacity(maximum);
        for el in self.assets.iter().keys().skip(skip).take(maximum) {
            let key = el?;
            let asset = Hash::from_bytes(&key)?;
            assets.insert(asset);
        }
        Ok(assets)
    }

    // Returns all assets that the key has
    async fn get_assets_for(&self, key: &PublicKey) -> Result<Vec<Hash>, BlockchainError> {
        self.balances.scan_prefix(key.as_bytes()).keys().map(|res| {
            let key = res?;
            // Keys are stored like this: [public key (32 bytes)][asset hash (32 bytes)]
            // See Self::get_balance_key_for
            Ok(Hash::from_bytes(&key[RISTRETTO_COMPRESSED_SIZE..])?)
        }).collect()
    }

    // count assets in storage
    async fn count_assets(&self) -> Result<u64, BlockchainError> {
        trace!("count assets");

        let count = if let Some(snapshot) = self.snapshot.as_ref() {
            snapshot.assets_count
        } else {
            self.assets_count
        };
        Ok(count)
    }

    async fn add_asset(&mut self, asset: &Hash, topoheight: TopoHeight, data: AssetData) -> Result<(), BlockchainError> {
        trace!("add asset {} at topoheight {}", asset, topoheight);
        let prev1 = Self::insert_into_disk(self.snapshot.as_mut(), &self.assets, asset.as_bytes(), &topoheight.to_be_bytes())?;

        let key = Self::get_asset_key(asset, topoheight);
        let prev2 = Self::insert_into_disk(self.snapshot.as_mut(), &self.assets_prefixed, &key, data.to_bytes())?;

        // Update counter
        if prev1.is_none() && prev2.is_none() {
            self.store_assets_count(self.count_assets().await? + 1)?;
        }

        if let Some(cache) = &self.assets_cache {
            let mut cache = cache.lock().await;
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