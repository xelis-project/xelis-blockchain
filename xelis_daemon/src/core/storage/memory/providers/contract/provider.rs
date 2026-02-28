use itertools::Either;
use pooled_arc::PooledArc;
use std::borrow::Cow;
use async_trait::async_trait;
use anyhow::Context;
use xelis_common::{
    account::CiphertextCache,
    asset::AssetData,
    block::TopoHeight,
    contract::ContractModule,
    crypto::{Hash, PublicKey},
    versioned::Versioned
};
use xelis_common::contract::{
    ContractStorage,
    ContractProvider as ContractInfoProvider,
};
use crate::core::{
    error::BlockchainError,
    storage::{
        AssetCirculatingSupplyProvider,
        AssetProvider,
        AccountProvider,
        BalanceProvider,
        ContractBalanceProvider,
        ContractDataProvider,
        ContractEventCallbackProvider,
        ContractProvider,
        ContractScheduledExecutionProvider,
        VersionedContractModule,
    },
};
use super::super::super::MemoryStorage;

#[async_trait]
impl ContractProvider for MemoryStorage {
    async fn set_last_contract_to<'a>(&mut self, hash: &Hash, topoheight: TopoHeight, contract: &VersionedContractModule<'a>) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(hash);
        self.contracts.entry(shared)
            .or_default()
            .modules
            .insert(topoheight, Versioned::new(contract.get().as_ref().map(|v| Cow::Owned(v.as_ref().clone())), contract.get_previous_topoheight()));

        Ok(())
    }

    async fn get_last_topoheight_for_contract(&self, hash: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.contracts.get(hash).and_then(|c| c.modules.last_key_value().map(|(t, _)| *t)))
    }

    async fn get_contract_at_topoheight_for<'a>(&self, hash: &Hash, topoheight: TopoHeight) -> Result<VersionedContractModule<'a>, BlockchainError> {
        self.contracts.get(hash)
            .and_then(|entry| entry.modules.get(&topoheight))
            .cloned()
            .with_context(|| format!("Contract module not found for contract {}, topoheight {}", hash, topoheight))
            .map_err(|e| e.into())
    }

    async fn get_contract_at_maximum_topoheight_for<'a>(&self, hash: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractModule<'a>)>, BlockchainError> {
        Ok(self.contracts.get(hash)
            .and_then(|entry| entry.modules.range(..=maximum_topoheight).next_back())
            .map(|(t, m)| (*t, m.clone()))
        )
    }

    async fn get_contracts<'a>(&'a self, minimum_topoheight: Option<TopoHeight>, maximum_topoheight: Option<TopoHeight>) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        Ok(self.contracts.iter()
            .filter_map(move |(hash, entry)| {
                match (minimum_topoheight, maximum_topoheight) {
                    (Some(min), Some(max)) => Either::Left(entry.modules.range(min..=max)),
                    (Some(min), None) => Either::Left(entry.modules.range(min..)),
                    (None, Some(max)) => Either::Left(entry.modules.range(..=max)),
                    (None, None) => Either::Right(entry.modules.iter()),
                }.next_back().map(|_| Ok(hash.as_ref().clone()))
            })
        )
    }

    async fn delete_last_topoheight_for_contract(&mut self, hash: &Hash) -> Result<(), BlockchainError> {
        self.contracts.get_mut(hash)
            .with_context(|| format!("Cannot delete contract module, contract not found: {}", hash))?
            .modules
            .pop_last();

        Ok(())
    }

    async fn has_contract_module_at_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.contracts.get(hash)
            .and_then(|entry| entry.modules.get(&topoheight))
            .map_or(false, |m| m.get().is_some()))
    }

    async fn has_contract_at_exact_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.contracts.get(hash)
            .map_or(false, |entry| entry.modules.contains_key(&topoheight)))
    }

    async fn has_contract_at_maximum_topoheight(&self, hash: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.contracts.get(hash)
            .and_then(|entry| entry.modules.range(..=topoheight).next_back())
            .map_or(false, |(_, m)| m.get().is_some()))
    }

    async fn count_contracts(&self) -> Result<u64, BlockchainError> {
        Ok(self.contracts.len() as u64)
    }

    async fn add_tx_for_contract(&mut self, contract: &Hash, tx: &Hash) -> Result<(), BlockchainError> {
        self.contracts.get_mut(contract)
            .map(|entry| {
                entry.transactions.insert(PooledArc::from_ref(tx));
            })
            .with_context(|| format!("Cannot add transaction for contract, contract not found: {}", contract))
            .map_err(|e| e.into())
    }

    async fn get_contract_transactions<'a>(&'a self, contract: &Hash) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        Ok(self.contracts.get(contract)
            .map(|entry| entry.transactions.iter().map(|tx| Ok(tx.as_ref().clone())))
            .into_iter()
            .flatten()
        )
    }
}

// ---- ContractStorage (xelis_common) ----

#[async_trait]
impl ContractStorage for MemoryStorage {
    async fn load_data(&self, contract: &Hash, key: &xelis_vm::ValueCell, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<xelis_vm::ValueCell>)>, anyhow::Error> {
        let res = self.get_contract_data_at_maximum_topoheight_for(contract, &key, topoheight).await?;

        match res {
            Some((topoheight, data)) => match data.take() {
                Some(data) => Ok(Some((topoheight, Some(data)))),
                None => Ok(Some((topoheight, None))),
            },
            None => Ok(None),
        }
    }

    async fn load_data_latest_topoheight(&self, contract: &Hash, key: &xelis_vm::ValueCell, topoheight: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error> {
        let res = self.get_contract_data_topoheight_at_maximum_topoheight_for(contract, &key, topoheight).await?;
        Ok(res)
    }

    async fn has_contract(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        let res = self.has_contract_at_maximum_topoheight(contract, topoheight).await?;
        Ok(res)
    }
}

// ---- ContractInfoProvider (xelis_common ContractProvider) ----

#[async_trait]
impl ContractInfoProvider for MemoryStorage {
    async fn get_contract_balance_for_asset(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, u64)>, anyhow::Error> {
        let res = self.get_contract_balance_at_maximum_topoheight(contract, asset, topoheight).await?;
        Ok(res.map(|(topoheight, balance)| (topoheight, balance.take())))
    }

    async fn asset_exists(&self, asset: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        let contains = self.is_asset_registered_at_maximum_topoheight(asset, topoheight).await?;
        Ok(contains)
    }

    async fn account_exists(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        let contains = self.is_account_registered_for_topoheight(key, topoheight).await?;
        Ok(contains)
    }

    // Verify if we have already a registered execution for such contract at a specific topoheight
    async fn has_scheduled_execution_at_topoheight(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        let contains = self.has_contract_scheduled_execution_at_topoheight(contract, topoheight).await?;
        Ok(contains)
    }

    // Load the asset data from the storage
    async fn load_asset_data(&self, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, AssetData)>, anyhow::Error> {
        let res = self.get_asset_at_maximum_topoheight(asset, topoheight).await?;
        Ok(res.map(|(topo, v)| (topo, v.take())))
    }

    async fn load_asset_circulating_supply(&self, asset: &Hash, topoheight: TopoHeight) -> Result<(TopoHeight, u64), anyhow::Error> {
        self.get_circulating_supply_for_asset_at_maximum_topoheight(asset, topoheight).await?
            .map(|(topo, v)| (topo, v.take()))
            .context("Asset circulating supply not found")
    }

    async fn get_account_balance_for_asset(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, CiphertextCache)>, anyhow::Error> {
        let res = self.get_balance_at_maximum_topoheight(key, asset, topoheight).await?;
        Ok(res.map(|(topoheight, balance)| (topoheight, balance.take_balance())))
    }

    // Load a contract module
    async fn load_contract_module(&self, contract: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<ContractModule>)>, anyhow::Error> {
        let res = self.get_contract_at_maximum_topoheight_for(contract, topoheight).await?;
        Ok(res.map(|(topoheight, module)| (topoheight, module.take().map(|v| v.into_owned()))))
    }

    // Check if a contract has already a callback registered for an event at topoheight
    async fn has_contract_callback_for_event(&self, contract: &Hash, event_id: u64, listener: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error> {
        let res = self.get_event_callback_for_contract_at_maximum_topoheight(contract, event_id, listener, topoheight).await?;
        Ok(res.is_some_and(|(_, v)| v.get().is_some()))
    }
}
