use async_trait::async_trait;
use xelis_common::{
    asset::{AssetData, VersionedAssetData},
    block::TopoHeight,
    crypto::{Hash, PublicKey},
};
use crate::core::{error::BlockchainError,
    storage::{
        rocksdb::{
            Asset,
            AssetId,
            Column
        },
        AssetProvider,
        RocksStorage
    }
};

pub const ASSETS_ID: &[u8] = b"ASID";

#[async_trait]
impl AssetProvider for RocksStorage {
    // Check if an asset exists
    async fn has_asset(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.contains_data(Column::Assets, hash)
    }

    // Check if an asset version exists at exact topoheight
    async fn has_asset_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        let asset = self.get_asset_type(hash)?;
        let key = Self::create_asset_versioned_key(topoheight, asset.id);

        self.contains_data(Column::VersionedAssets, &key)
    }

    // Get the asset topoheight at which it got registered
    async fn get_asset_topoheight(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        let Some(asset) = self.get_optional_asset_type(hash)? else {
            return Ok(None)
        };

        Ok(asset.data_pointer)
    }

    // Get the asset data from its hash and topoheight at which it got registered
    async fn get_asset_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedAssetData, BlockchainError> {
        let asset = self.get_asset_type(hash)?;
        let key = Self::create_asset_versioned_key(topoheight, asset.id);

        self.load_from_disk(Column::VersionedAssets, &key)
    }

    // Check that the asset has been registered <= maximum topoheight  
    async fn is_asset_registered_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Get asset data for topoheight
    // This check that asset topoheight is <= requested topoheight
    async fn get_asset_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedAssetData)>, BlockchainError> {
        todo!()
    }

    // Get the asset data from its hash and topoheight at which it got registered
    async fn get_asset(&self, hash: &Hash) -> Result<(TopoHeight, VersionedAssetData), BlockchainError> {
        let asset = self.get_asset_type(hash)?;
        let topoheight = asset.data_pointer
            .ok_or_else(|| BlockchainError::AssetNotFound(hash.clone()))?;

        let key = Self::create_asset_versioned_key(topoheight, asset.id);
        let data = self.load_from_disk(Column::VersionedAssets, &key)?;

        Ok((topoheight, data))
    }

    // Get all available assets
    async fn get_assets<'a>(&'a self) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        self.iter_keys(Column::Assets)
    }

    // Get all available assets with their Asset Data in specified range
    async fn get_assets_with_data_in_range<'a>(&'a self, minimum_topoheight: Option<u64>, maximum_topoheight: Option<u64>) -> Result<impl Iterator<Item = Result<(Hash, TopoHeight, AssetData), BlockchainError>> + 'a, BlockchainError> {
        Ok(self.iter::<Hash, Asset>(Column::Assets)?
            .map(move |res| {
                let (asset, metadata) = res?;

                let Some(topoheight) = metadata.data_pointer else {
                    return Ok(None)
                };

                if minimum_topoheight.is_some_and(|v| topoheight < v) || maximum_topoheight.is_some_and(|v| topoheight > v) {
                    return Ok(None)
                }

                let key = Self::create_asset_versioned_key(topoheight, metadata.id);
                match self.load_optional_from_disk::<_, VersionedAssetData>(Column::VersionedAssets, &key)? {
                    Some(data) => Ok(Some((asset, topoheight, data.take()))),
                    None => Ok(None)
                }
            })
            .filter_map(Result::transpose)
        )
    }

    // Get all assets for a specific key
    async fn get_assets_for(&self, key: &PublicKey) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>>, BlockchainError> {
        // TODO: find account id, and read balances
        Ok(std::iter::empty())
    }

    // Count the number of assets stored
    async fn count_assets(&self) -> Result<u64, BlockchainError> {
        // TODO: cache
        self.load_optional_from_disk(Column::Common, &ASSETS_ID).map(|v| v.unwrap_or(0))
    }

    // Add an asset to the storage
    async fn add_asset(&mut self, hash: &Hash, topoheight: TopoHeight, data: VersionedAssetData) -> Result<(), BlockchainError> {
        // Load it from storage if an id was already assigned to it
        let asset = if let Some(mut asset) = self.get_optional_asset_type(hash)? {
            asset.data_pointer = Some(topoheight);
            asset
        } else {
            let id = self.get_next_asset_id()?;
            Asset {
                id,
                data_pointer: Some(topoheight),
                supply_pointer: None
            }
        };

        self.insert_into_disk(Column::Assets, hash, &asset)?;

        let key = Self::create_asset_versioned_key(topoheight, asset.id);
        self.insert_into_disk(Column::VersionedAssets, &key, &data)
    }
}

impl RocksStorage {
    fn get_next_asset_id(&mut self) -> Result<AssetId, BlockchainError> {
        let id = self.load_optional_from_disk(Column::Common, &ASSETS_ID)?
            .unwrap_or(0);
        self.insert_into_disk(Column::Common, &ASSETS_ID, &(id + 1))?;

        Ok(id)
    }

    fn get_optional_asset_type(&self, hash: &Hash) -> Result<Option<Asset>, BlockchainError> {
        self.load_optional_from_disk(Column::Assets, hash)
    }

    fn get_asset_type(&self, hash: &Hash) -> Result<Asset, BlockchainError> {
        self.load_from_disk(Column::Assets, hash)
    }

    fn create_asset_versioned_key(topoheight: TopoHeight, id: AssetId) -> [u8; 16] {
        let mut buffer = [0u8; 16];

        buffer[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buffer[8..].copy_from_slice(&id.to_be_bytes());

        buffer
    }
}