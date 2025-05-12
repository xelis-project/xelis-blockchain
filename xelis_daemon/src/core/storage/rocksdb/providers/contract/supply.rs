use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
    versioned_type::Versioned
};
use crate::core::{error::BlockchainError, storage::{RocksStorage, SupplyProvider}};

pub type VersionedSupply = Versioned<u64>;

#[async_trait]
impl SupplyProvider for RocksStorage {
    // Verify if we have a supply already set for this asset
    async fn has_supply_for_asset(&self, asset: &Hash) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Verify if we have a versioned data at exact topoheight
    async fn has_asset_supply_at_exact_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        todo!()
    }

    // Get the latest supply topoheight for asset
    async fn get_last_topoheight_for_asset_supply(&self, asset: &Hash) -> Result<TopoHeight, BlockchainError> {
        todo!()
    }

    // Get a versioned supply at a specific topoheight
    async fn get_asset_supply_at_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedSupply, BlockchainError> {
        todo!()
    }

    // Get the supply at the maximum topoheight
    async fn get_asset_supply_at_maximum_topoheight(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError> {
        todo!()
    }

    // Set the latest supply pointer for this asset and store the versioned data
    async fn set_last_supply_for_asset(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError> {
        todo!()
    }

    // Set the topoheight as last pointer for the asset supply
    async fn set_last_topoheight_for_asset_supply(&mut self, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        todo!()
    }

    // Store the versioned supply to a specific topoheight
    async fn set_asset_supply_at_topoheight(&mut self, asset: &Hash, topoheight: TopoHeight, supply: &VersionedSupply) -> Result<(), BlockchainError> {
        todo!()
    }
}