use async_trait::async_trait;
use log::trace;
use xelis_common::{
    asset::{AssetData, VersionedAssetData},
    block::TopoHeight,
    crypto::{Hash, PublicKey},
    serializer::Skip,
};
use crate::core::{error::BlockchainError,
    storage::{
        rocksdb::{
            Asset,
            AssetId,
            Column,
            IteratorMode,
        },
        snapshot::Direction,
        AssetProvider,
        NetworkProvider,
        RocksStorage
    }
};

pub const ASSETS_ID: &[u8] = b"ASID";

#[async_trait]
impl AssetProvider for RocksStorage {
    // Check if an asset exists
    async fn has_asset(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        trace!("has asset {}", hash);
        self.contains_data(Column::Assets, hash)
    }

    // Check if an asset version exists at exact topoheight
    async fn has_asset_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has asset {} at topoheight {}", hash, topoheight);
        let asset = self.get_asset_type(hash)?;
        let key = Self::get_asset_versioned_key(topoheight, asset.id);

        self.contains_data(Column::VersionedAssets, &key)
    }

    // Get the asset topoheight at which it got registered
    async fn get_asset_topoheight(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        trace!("get asset {} topoheight", hash);
        let Some(asset) = self.get_optional_asset_type(hash)? else {
            trace!("asset {} not found", hash);
            return Ok(None)
        };

        Ok(asset.data_pointer)
    }

    // Get the asset data from its hash and topoheight at which it got registered
    async fn get_asset_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedAssetData, BlockchainError> {
        trace!("get asset {} at topoheight {}", hash, topoheight);
        let asset = self.get_asset_type(hash)?;
        self.get_asset_at_topoheight_internal(asset.id, topoheight)
    }

    // Check that the asset has been registered <= maximum topoheight  
    async fn is_asset_registered_at_maximum_topoheight(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("is asset {} registered at maximum topoheight {}", hash, maximum_topoheight);
        let topoheight = self.get_asset_topoheight(hash).await?;
        match topoheight {
            Some(topo) if topo <= maximum_topoheight => Ok(true),
            _ => Ok(false)
        }
    }

    // Get asset data for topoheight
    // This check that asset topoheight is <= requested topoheight
    async fn get_asset_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedAssetData)>, BlockchainError> {
        trace!("get asset {} at maximum topoheight {}", hash, topoheight);
        let Some(metadata) = self.get_optional_asset_type(hash)? else {
            trace!("asset {} not found", hash);
            return Ok(None)
        };

        let mut topo = metadata.data_pointer;
        while let Some(previous) = topo {
            if previous <= topoheight {
                trace!("asset {} found at topoheight {}", hash, previous);
                let data = self.get_asset_at_topoheight_internal(metadata.id, previous)?;
                return Ok(Some((previous, data)))
            }

            let key = Self::get_asset_versioned_key(topoheight, metadata.id);
            topo = self.load_from_disk(Column::VersionedAssets, &key)?;
        }

        Ok(None)
    }

    // Get the asset data from its hash and topoheight at which it got registered
    async fn get_asset(&self, hash: &Hash) -> Result<(TopoHeight, VersionedAssetData), BlockchainError> {
        trace!("get asset {}", hash);
        let asset = self.get_asset_type(hash)?;
        let topoheight = asset.data_pointer
            .ok_or_else(|| BlockchainError::AssetNotFound(hash.clone()))?;

        let data = self.get_asset_at_topoheight_internal(asset.id, topoheight)?;

        Ok((topoheight, data))
    }

    // Get all available assets
    async fn get_assets<'a>(&'a self) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("get assets");
        self.iter_keys(Column::Assets, IteratorMode::Start)
    }

    // Get all available assets with their Asset Data in specified range
    async fn get_assets_with_data_in_range<'a>(&'a self, minimum_topoheight: Option<u64>, maximum_topoheight: Option<u64>) -> Result<impl Iterator<Item = Result<(Hash, TopoHeight, AssetData), BlockchainError>> + 'a, BlockchainError> {
        trace!("get assets with data in range minimum_topoheight: {:?}, maximum_topoheight: {:?}", minimum_topoheight, maximum_topoheight);
        Ok(self.iter::<Hash, Asset>(Column::Assets, IteratorMode::Start)?
            .map(move |res| {
                let (asset, metadata) = res?;

                let Some(topoheight) = metadata.data_pointer else {
                    return Ok(None)
                };

                if minimum_topoheight.is_some_and(|v| topoheight < v) || maximum_topoheight.is_some_and(|v| topoheight > v) {
                    return Ok(None)
                }

                let key = Self::get_asset_versioned_key(topoheight, metadata.id);
                match self.load_optional_from_disk::<_, VersionedAssetData>(Column::VersionedAssets, &key)? {
                    Some(data) => Ok(Some((asset, topoheight, data.take()))),
                    None => Ok(None)
                }
            })
            .filter_map(Result::transpose)
        )
    }

    // Get all assets for a specific key
    async fn get_assets_for<'a>(&'a self, key: &'a PublicKey) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        trace!("get assets for {}", key.as_address(self.is_mainnet()));
        let account_id = self.get_account_id(key)?;
        self.iter_keys::<Skip<8, AssetId>>(Column::Balances, IteratorMode::WithPrefix(&account_id.to_be_bytes(), Direction::Forward))
            .map(|iter| iter.map(|res| {
                let k = res?;
                self.get_asset_hash_from_id(k.0)
            }))
    }

    // Count the number of assets stored
    async fn count_assets(&self) -> Result<u64, BlockchainError> {
        trace!("count assets");
        // TODO: cache
        self.load_optional_from_disk(Column::Common, &ASSETS_ID).map(|v| v.unwrap_or(0))
    }

    // Add an asset to the storage
    async fn add_asset(&mut self, hash: &Hash, topoheight: TopoHeight, data: VersionedAssetData) -> Result<(), BlockchainError> {
        trace!("add asset {} at topoheight {}", hash, topoheight);
        // Load it from storage if an id was already assigned to it
        let asset = if let Some(mut asset) = self.get_optional_asset_type(hash)? {
            asset.data_pointer = Some(topoheight);
            asset
        } else {
            let id = self.get_next_asset_id()?;
            let asset = Asset {
                id,
                data_pointer: Some(topoheight),
                supply_pointer: None
            };

            self.insert_into_disk(Column::AssetById, &id.to_be_bytes(), hash)?;

            asset
        };

        self.insert_into_disk(Column::Assets, hash, &asset)?;

        let key = Self::get_asset_versioned_key(topoheight, asset.id);
        self.insert_into_disk(Column::VersionedAssets, &key, &data)
    }
}

impl RocksStorage {
    fn get_next_asset_id(&mut self) -> Result<AssetId, BlockchainError> {
        trace!("get next asset id");
        let id = self.load_optional_from_disk(Column::Common, &ASSETS_ID)?
            .unwrap_or(0);

        trace!("next asset id: {}", id);
        self.insert_into_disk(Column::Common, &ASSETS_ID, &(id + 1))?;

        Ok(id)
    }

    fn get_asset_at_topoheight_internal(&self, id: AssetId, topoheight: TopoHeight) -> Result<VersionedAssetData, BlockchainError> {
        trace!("get asset at topoheight internal {} {}", id, topoheight);
        let key = Self::get_asset_versioned_key(topoheight, id);
        self.load_from_disk(Column::VersionedAssets, &key)
    }

    pub(super) fn get_optional_asset_type(&self, hash: &Hash) -> Result<Option<Asset>, BlockchainError> {
        trace!("get optional asset {}", hash);
        self.load_optional_from_disk(Column::Assets, hash)
    }

    pub(super) fn get_asset_type(&self, hash: &Hash) -> Result<Asset, BlockchainError> {
        trace!("get asset type {}", hash);
        self.load_from_disk(Column::Assets, hash)
    }

    pub(super) fn get_optional_asset_id(&self, hash: &Hash) -> Result<Option<AssetId>, BlockchainError> {
        trace!("get optional asset id {}", hash);
        self.load_optional_from_disk(Column::Assets, hash)
    }

    pub(super) fn get_asset_id(&self, hash: &Hash) -> Result<AssetId, BlockchainError> {
        trace!("get asset id {}", hash);
        self.get_optional_asset_id(hash)?
            .ok_or_else(|| BlockchainError::AssetNotFound(hash.clone()))
    }

    pub(super) fn get_asset_hash_from_id(&self, id: AssetId) -> Result<Hash, BlockchainError> {
        trace!("get asset hash from id id {}", id);
        self.load_from_disk(Column::AssetById, &id.to_be_bytes())
    }

    pub(super) fn get_asset_versioned_key(topoheight: TopoHeight, id: AssetId) -> [u8; 16] {
        let mut buffer = [0u8; 16];

        buffer[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buffer[8..].copy_from_slice(&id.to_be_bytes());

        buffer
    }
}