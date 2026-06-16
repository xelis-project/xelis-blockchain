use std::collections::HashMap;

use async_trait::async_trait;
use xelis_vm::{ValueCell, tid};

use crate::{
    account::CiphertextCache,
    asset::AssetData,
    block::*,
    contract::{
        ContractModule,
        ContractProvider,
        ContractStorage,
    },
    crypto::Hash,
};

#[derive(Debug, Default, Clone)]
pub struct MockStorageProvider {
    pub contracts: HashMap<Hash, HashMap<ValueCell, (TopoHeight, Option<ValueCell>)>>,
}

tid!(MockStorageProvider);

#[async_trait]
impl ContractStorage for MockStorageProvider {
    async fn load_data(
        &self,
        contract: &Hash,
        key: &ValueCell,
        _: TopoHeight,
    ) -> Result<Option<(TopoHeight, Option<ValueCell>)>, anyhow::Error> {
        Ok(self.contracts.get(contract).and_then(|c| c.get(key).cloned()))
    }

    async fn load_data_latest_topoheight(
        &self,
        contract: &Hash,
        key: &ValueCell,
        _: TopoHeight,
    ) -> Result<Option<TopoHeight>, anyhow::Error> {
        Ok(self
            .contracts
            .get(contract)
            .and_then(|c| c.get(key))
            .map(|(topo, _)| *topo))
    }

    async fn has_contract(&self, contract: &Hash, _: TopoHeight) -> Result<bool, anyhow::Error> {
        Ok(self.contracts.contains_key(contract))
    }
}

#[async_trait]
impl<'ty> ContractProvider<'ty> for MockStorageProvider {
    async fn get_contract_balance_for_asset(
        &self,
        _: &Hash,
        _: &Hash,
        _: TopoHeight,
    ) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        Ok(None)
    }

    async fn get_account_balance_for_asset(
        &self,
        _: &crate::crypto::PublicKey,
        _: &Hash,
        _: TopoHeight,
    ) -> Result<Option<(TopoHeight, CiphertextCache)>, anyhow::Error> {
        Ok(None)
    }

    async fn has_scheduled_execution_at_topoheight(
        &self,
        _: &Hash,
        _: TopoHeight,
    ) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn asset_exists(&self, _: &Hash, _: TopoHeight) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn load_asset_data(
        &self,
        _: &Hash,
        _: TopoHeight,
    ) -> Result<Option<(TopoHeight, AssetData)>, anyhow::Error> {
        Ok(None)
    }

    async fn load_asset_circulating_supply(
        &self,
        _: &Hash,
        _: TopoHeight,
    ) -> Result<(TopoHeight, u64), anyhow::Error> {
        Ok((0, 0))
    }

    async fn account_exists(
        &self,
        _: &crate::crypto::PublicKey,
        _: TopoHeight,
    ) -> Result<bool, anyhow::Error> {
        Ok(false)
    }

    async fn load_contract_module(
        &self,
        _: &Hash,
        _: TopoHeight,
    ) -> Result<Option<(TopoHeight, Option<ContractModule>)>, anyhow::Error> {
        Ok(None)
    }

    async fn has_contract_callback_for_event(
        &self,
        _: &Hash,
        _: u64,
        _: &Hash,
        _: TopoHeight,
    ) -> Result<bool, anyhow::Error> {
        Ok(false)
    }
}
