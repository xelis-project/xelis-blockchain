use xelis_vm::tid;

use crate::{asset::AssetData, block::TopoHeight, crypto::{Hash, PublicKey}};

use super::ContractStorage;

pub trait ContractProvider: ContractStorage + 'static {
    // Returns the balance of the contract
    fn get_contract_balance_for_asset(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error>;

    // Verify if an asset exists in the storage
    fn asset_exists(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;

    // Load the asset data from the storage
    fn load_asset_data(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, AssetData)>, anyhow::Error>;

    // Load the asset supply
    fn load_asset_supply(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error>;

    // Verify if the address is well registered
    fn account_exists(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;
}

// This is a wrapper around the storage to allow for the storage to be passed in the Context
pub struct ContractProviderWrapper<'a, S: ContractProvider>(pub &'a mut S);

tid! { impl<'a, S: 'static> TidAble<'a> for ContractProviderWrapper<'a, S> where S: ContractProvider }
