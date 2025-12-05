use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    versioned_type::Versioned
};
use crate::core::error::BlockchainError;

pub type VersionedSupply = Versioned<u64>;

// Circulating Supply Provider is used for non-native assets being tracked
// We don't track the emitted and burned amount because, based on the Contract
// implementation it may create overflow which not would be healthy data on long term
// (in case of mint/burn mechanisms).
// Only the circulating supply can be ensured to be valid in the 0..2^64 range
#[async_trait]
pub trait AssetCirculatingSupplyProvider {
    // Verify if we have a supply already set for this asset
    async fn has_circulating_supply_for_asset(&self, asset: &Hash) -> Result<bool, BlockchainError>;

    // Verify if we have a versioned data at exact topoheight
    async fn has_circulating_supply_for_asset_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the supply at exact topoheight
    async fn get_circulating_supply_for_asset_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedSupply, BlockchainError>;

    // Get the supply at the maximum topoheight
    async fn get_circulating_supply_for_asset_at_maximum_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError>;

    // Set the latest supply pointer for this asset and store the versioned data
    async fn set_last_circulating_supply_for_asset(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError>;
}