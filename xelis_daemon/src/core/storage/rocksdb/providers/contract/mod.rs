mod data;
mod output;
mod balance;
mod supply;
mod r#impl;

use async_trait::async_trait;
use xelis_common::{
    account::CiphertextCache,
    asset::AssetData,
    block::TopoHeight,
    contract::{ContractProvider as ContractAccess, ContractStorage},
    crypto::{Hash, PublicKey}
};
use xelis_vm::ValueCell;
use crate::core::storage::RocksStorage;

#[async_trait]
impl ContractAccess for RocksStorage {
    // Returns the balance of the contract
    fn get_contract_balance_for_asset(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        todo!()
    }

    // Get the account balance for asset
    fn get_account_balance_for_asset(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, CiphertextCache)>, anyhow::Error> {
        todo!()
    }

    // Verify if an asset exists in the storage
    fn asset_exists(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        todo!()
    }

    // Load the asset data from the storage
    fn load_asset_data(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, AssetData)>, anyhow::Error> {
        todo!()
    }

    // Load the asset supply
    fn load_asset_supply(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        todo!()
    }

    // Verify if the address is well registered
    fn account_exists(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        todo!()
    }
}

impl ContractStorage for RocksStorage {
    // load a value from the storage
    fn load_data(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<ValueCell>)>, anyhow::Error> {
        todo!()
    }

    // load the latest topoheight from the storage
    fn load_data_latest_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error> {
        todo!()
    }

    // check if a key exists in the storage
    fn has_data(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        todo!()
    }

    // check if a contract hash exists in the storage
    fn has_contract(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        todo!()
    }
}