use std::sync::Arc;
use async_trait::async_trait;
use log::trace;
use xelis_common::{
    asset::AssetData,
    block::TopoHeight,
    contract::{ContractProvider, ContractStorage},
    account::CiphertextCache,
    crypto::{Hash, PublicKey},
};
use xelis_vm::{Module, ValueCell};
use crate::core::storage::{
    AccountProvider,
    AssetProvider,
    BalanceProvider,
    ContractBalanceProvider,
    ContractDataProvider,
    ContractProvider as _,
    NetworkProvider,
    SledStorage,
    SupplyProvider
};

#[async_trait]
impl ContractStorage for SledStorage {
    async fn load_data(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<ValueCell>)>, anyhow::Error> {
        trace!("load contract {} key {} data at topoheight {}", contract, key, topoheight);
        let res = self.get_contract_data_at_maximum_topoheight_for(contract, &key, topoheight).await?;

        match res {
            Some((topoheight, data)) => match data.take() {
                Some(data) => Ok(Some((topoheight, Some(data)))),
                None => Ok(Some((topoheight, None))),
            },
            None => Ok(None),
        }
    }

    async fn load_data_latest_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error> {
        trace!("load data latest topoheight for contract {} key {} at topoheight {}", contract, key, topoheight);
        let res = self.get_contract_data_topoheight_at_maximum_topoheight_for(contract, &key, topoheight).await?;
        Ok(res)
    }

    async fn has_contract(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        trace!("has contract {} at topoheight {}", contract, topoheight);
        let res = self.has_contract_at_maximum_topoheight(contract, topoheight).await?;
        Ok(res)
    }
}

#[async_trait]
impl ContractProvider for SledStorage {
    async fn get_contract_balance_for_asset(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        trace!("get contract balance for contract {} asset {}", contract, asset);
        let res = self.get_contract_balance_at_maximum_topoheight(contract, asset, topoheight).await?;
        Ok(res.map(|(topoheight, balance)| (topoheight, balance.take())))
    }

    async fn asset_exists(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        trace!("check if asset {} exists at topoheight {}", asset, topoheight);
        let contains = self.is_asset_registered_at_maximum_topoheight(asset, topoheight).await?;
        Ok(contains)
    }

    async fn account_exists(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        trace!("check if account {} exists at topoheight {}", key.as_address(self.is_mainnet()), topoheight);

        let contains = self.is_account_registered_for_topoheight(key, topoheight).await?;
        Ok(contains)
    }

    // Load the asset data from the storage
    async fn load_asset_data(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, AssetData)>, anyhow::Error> {
        trace!("load asset data for asset {} at topoheight {}", asset, topoheight);
        let res = self.get_asset_at_maximum_topoheight(asset, topoheight).await?;
        Ok(res.map(|(topo, v)| (topo, v.take())))
    }

    async fn load_asset_supply(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        trace!("load asset supply for asset {} at topoheight {}", asset, topoheight);
        let res = self.get_asset_supply_at_maximum_topoheight(asset, topoheight).await?;
        Ok(res.map(|(topoheight, supply)| (topoheight, supply.take())))
    }

    async fn get_account_balance_for_asset(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, CiphertextCache)>, anyhow::Error> {
        trace!("get account {} balance for asset {} at topoheight {}", key.as_address(self.is_mainnet()), asset, topoheight);
        let res = self.get_balance_at_maximum_topoheight(key, asset, topoheight).await?;
        Ok(res.map(|(topoheight, balance)| (topoheight, balance.take_balance())))
    }

    // Load a contract module
    async fn load_contract_module(&self, contract: &Hash, topoheight: TopoHeight) -> Result<Option<Arc<Module>>, anyhow::Error> {
        trace!("load contract module for contract {} at topoheight {}", contract, topoheight);
        let res = self.get_contract_at_maximum_topoheight_for(contract, topoheight).await?;
        Ok(res.and_then(|(_, module)| module.take().map(|v| Arc::new(v.into_owned()))))
    }
}