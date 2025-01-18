use log::trace;
use xelis_common::{asset::AssetData, block::TopoHeight, contract::{ContractProvider, ContractStorage}, crypto::{Hash, PublicKey}};
use xelis_vm::Constant;
use crate::core::storage::{AccountProvider, AssetProvider, ContractBalanceProvider, ContractDataProvider, NetworkProvider, SledStorage, SupplyProvider};

impl ContractStorage for SledStorage {
    fn load_data(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<Constant>)>, anyhow::Error> {
        trace!("load contract {} key {} data at topoheight {}", contract, key, topoheight);
        let res = futures::executor::block_on(self.get_contract_data_at_maximum_topoheight_for(contract, &key, topoheight))?;

        match res {
            Some((topoheight, data)) => match data.take() {
                Some(data) => Ok(Some((topoheight, Some(data)))),
                None => Ok(Some((topoheight, None))),
            },
            None => Ok(None),
        }
    }

    fn has_data(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        trace!("check if contract {} key {} data exists at topoheight {}", contract, key, topoheight);
        let contains = futures::executor::block_on(self.has_contract_data_at_topoheight(contract, &key, topoheight))?;
        Ok(contains)
    }

    fn load_data_latest_topoheight(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error> {
        trace!("load data latest topoheight for contract {} key {} at topoheight {}", contract, key, topoheight);
        let res = futures::executor::block_on(self.get_contract_data_topoheight_at_maximum_topoheight_for(contract, &key, topoheight))?;
        Ok(res)
    }
}

impl ContractProvider for SledStorage {
    fn get_contract_balance_for_asset(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        trace!("get contract balance for contract {} asset {}", contract, asset);
        let res =futures::executor::block_on(self.get_contract_balance_at_maximum_topoheight(contract, asset, topoheight))?;
        Ok(res.map(|(topoheight, balance)| (topoheight, balance.take())))
    }

    fn asset_exists(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        trace!("check if asset {} exists at topoheight {}", asset, topoheight);
        let contains = futures::executor::block_on(self.has_asset_at_topoheight(asset, topoheight))?;
        Ok(contains)
    }

    fn account_exists(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        trace!("check if account {} exists at topoheight {}", key.as_address(self.is_mainnet()), topoheight);

        let contains = futures::executor::block_on(self.is_account_registered_for_topoheight(key, topoheight))?;
        Ok(contains)
    }

    // Load the asset data from the storage
    fn load_asset_data(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, AssetData)>, anyhow::Error> {
        trace!("load asset data for asset {} at topoheight {}", asset, topoheight);
        let res = futures::executor::block_on(self.get_asset_with_topoheight(asset, topoheight))?;
        Ok(res)
    }

    fn load_asset_supply(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        trace!("load asset supply for asset {} at topoheight {}", asset, topoheight);
        let res = futures::executor::block_on(self.get_asset_supply_at_maximum_topoheight(asset, topoheight))?;
        Ok(res.map(|(topoheight, supply)| (topoheight, supply.take())))
    }
}