use std::sync::atomic::Ordering;
use async_trait::async_trait;
use indexmap::IndexSet;
use log::trace;
use xelis_common::{
    asset::{AssetData, AssetWithData},
    crypto::{Hash, HASH_SIZE, PublicKey},
    serializer::Serializer,
};
use crate::core::{
    error::BlockchainError,
    storage::SledStorage,
};

#[async_trait]
pub trait AssetProvider {
    // Check if an asset exists
    async fn has_asset(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Get the asset data from its hash
    async fn get_asset(&self, hash: &Hash) -> Result<AssetData, BlockchainError>;

    // Get all available assets
    // TODO: replace with impl Iterator<Item = Result<Hash, BlockchainError>> when async trait methods are stable
    async fn get_assets(&self) -> Result<Vec<Hash>, BlockchainError>;

    // Get a partial list of assets supporting pagination and filtering by topoheight
    // TODO: replace with impl Iterator<Item = Result<Hash, BlockchainError>> when async trait methods are stable
    async fn get_partial_assets(&self, maximum: usize, skip: usize, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<IndexSet<AssetWithData>, BlockchainError>;

    // Get chunked assets
    // This is useful to not retrieve all assets at once
    async fn get_chunked_assets(&self, maximum: usize, skip: usize) -> Result<IndexSet<Hash>, BlockchainError>;

    // Get all assets for a specific key
    // TODO: replace with impl Iterator<Item = Result<Hash, BlockchainError>> when async trait methods are stable
    async fn get_assets_for(&self, key: &PublicKey) -> Result<Vec<Hash>, BlockchainError>;

    // Count the number of assets stored
    async fn count_assets(&self) -> Result<u64, BlockchainError>;

    // Add an asset to the storage
    async fn add_asset(&mut self, hash: &Hash, data: AssetData) -> Result<(), BlockchainError>;
}

#[async_trait]
impl AssetProvider for SledStorage {
    async fn has_asset(&self, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("asset exist {}", asset);
        self.contains_data(&self.assets, &self.assets_cache, asset).await
    }

    async fn get_asset(&self, asset: &Hash) -> Result<AssetData, BlockchainError> {
        trace!("get asset registration topoheight {}", asset);
        self.load_from_disk(&self.assets, asset.as_bytes())
    }

    // we are forced to read from disk directly because cache may don't have all assets in memory
    async fn get_assets(&self) -> Result<Vec<Hash>, BlockchainError> {
        trace!("get assets");

        self.assets.iter().keys().map(|res| {
            let key = res?;
            Ok(Hash::new(key[0..HASH_SIZE].try_into()?))
        }).collect()
    }

    async fn get_partial_assets(&self, maximum: usize, skip: usize, minimum_topoheight: u64, maximum_topoheight: u64) -> Result<IndexSet<AssetWithData>, BlockchainError> {
        let mut assets = IndexSet::new();
        let mut skip_count = 0;
        for el in self.assets.iter() {
            let (key, value) = el?;
            let data = AssetData::from_bytes(&value)?;
            // check that we have a registered asset before the maximum topoheight
            if data.get_topoheight() >= minimum_topoheight && data.get_topoheight() <= maximum_topoheight {
                if skip_count < skip {
                    skip_count += 1;
                } else {
                    let asset = Hash::from_bytes(&key)?;
                    assets.insert(AssetWithData::new(asset, data));

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
            Ok(Hash::new(key[HASH_SIZE..HASH_SIZE*2].try_into()?))
        }).collect()
    }

    // count assets in storage
    async fn count_assets(&self) -> Result<u64, BlockchainError> {
        trace!("count assets");
        Ok(self.assets_count.load(Ordering::SeqCst))
    }

    async fn add_asset(&mut self, asset: &Hash, data: AssetData) -> Result<(), BlockchainError> {
        trace!("add asset {} at topoheight {}", asset, data.get_topoheight());
        self.assets.insert(asset.as_bytes(), data.to_bytes())?;

        // Update counter
        self.store_assets_count(self.count_assets().await? + 1)?;

        if let Some(cache) = &self.assets_cache {
            let mut cache = cache.lock().await;
            cache.put(asset.clone(), ());
        }
        Ok(())
    }
}