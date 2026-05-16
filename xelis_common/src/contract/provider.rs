use async_trait::async_trait;
use runtime_context::ShareableTid;

use crate::{
    account::CiphertextCache,
    contract::ContractModule,
    asset::AssetData,
    block::TopoHeight,
    crypto::{Hash, PublicKey}
};

use super::ContractStorage;

#[async_trait]
pub trait ContractProvider<'ty>: ContractStorage + ShareableTid<'ty> {
    // Returns the balance of the contract
    async fn get_contract_balance_for_asset(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error>;

    // Get the account balance for asset
    async fn get_account_balance_for_asset(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, CiphertextCache)>, anyhow::Error>;

    // Verify if we have already a registered execution for such contract at a specific topoheight
    async fn has_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;

    // Verify if an asset exists in the storage
    async fn asset_exists(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;

    // Load the asset data from the storage
    async fn load_asset_data(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, AssetData)>, anyhow::Error>;

    // Load the asset supply
    // Supply is the current circulating supply
    async fn load_asset_circulating_supply(&self, asset: &Hash, topoheight: TopoHeight) -> Result<(TopoHeight, u64), anyhow::Error>;

    // Verify if the address is well registered
    async fn account_exists(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;

    // Load a contract module
    async fn load_contract_module(&self, contract: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<ContractModule>)>, anyhow::Error>;

    // Check if a contract has already a callback registered for an event at maximum topoheight
    async fn has_contract_callback_for_event(&self, contract: &Hash, event_id: u64, listener: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;
}
