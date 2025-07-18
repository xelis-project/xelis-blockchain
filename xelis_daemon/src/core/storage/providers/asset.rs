use async_trait::async_trait;
use xelis_common::{
    asset::{AssetData, VersionedAssetData},
    block::TopoHeight,
    crypto::{Hash, PublicKey},
};
use crate::core::error::BlockchainError;

#[async_trait]
pub trait AssetProvider {
    // Check if an asset exists
    async fn has_asset(&self, hash: &Hash) -> Result<bool, BlockchainError>;

    // Check if an asset version exists at exact topoheight
    async fn has_asset_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the asset topoheight at which it got registered
    async fn get_asset_topoheight(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError>;

    // Get the asset data from its hash and topoheight at which it got registered
    async fn get_asset_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedAssetData, BlockchainError>;

    // Check that the asset has been registered <= maximum topoheight  
    async fn is_asset_registered_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get asset data for topoheight
    // This check that asset topoheight is <= requested topoheight
    async fn get_asset_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedAssetData)>, BlockchainError>;

    // Get the asset data from its hash and topoheight at which it got registered
    async fn get_asset(&self, hash: &Hash) -> Result<(TopoHeight, VersionedAssetData), BlockchainError>;

    // Get all available assets
    async fn get_assets<'a>(&'a self) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError>;

    // Get all available assets with their Asset Data in specified range
    async fn get_assets_with_data_in_range<'a>(&'a self, minimum_topoheight: Option<u64>, maximum_topoheight: Option<u64>) -> Result<impl Iterator<Item = Result<(Hash, TopoHeight, AssetData), BlockchainError>> + 'a, BlockchainError>;

    // Get all assets for a specific key
    async fn get_assets_for<'a>(&'a self, key: &'a PublicKey) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError>;

    // Count the number of assets stored
    async fn count_assets(&self) -> Result<u64, BlockchainError>;

    // Add an asset to the storage
    async fn add_asset(&mut self, hash: &Hash, topoheight: TopoHeight, data: VersionedAssetData) -> Result<(), BlockchainError>;
}