use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    versioned_type::Versioned
};
use crate::core::error::BlockchainError;

pub type VersionedSupply = Versioned<u64>;

#[async_trait]
pub trait SupplyProvider {
    // Verify if we have a supply already set for this asset
    async fn has_supply_for_asset(&self, asset: &Hash) -> Result<bool, BlockchainError>;

    // Verify if we have a versioned data at exact topoheight
    async fn has_asset_supply_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the supply at the maximum topoheight
    async fn get_asset_supply_at_maximum_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError>;

    // Set the latest supply pointer for this asset and store the versioned data
    async fn set_last_supply_for_asset(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError>;
}