use pooled_arc::PooledArc;
use async_trait::async_trait;
use anyhow::Context;
use xelis_common::{
    block::TopoHeight,
    crypto::Hash,
};
use crate::core::storage::VersionedContractBalance;
use crate::core::{
    error::BlockchainError,
    storage::ContractBalanceProvider,
};
use super::super::super::MemoryStorage;

#[async_trait]
impl ContractBalanceProvider for MemoryStorage {
    async fn has_contract_balance_for(&self, contract: &Hash, asset: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.contracts.get(contract)
            .and_then(|entry| entry.balances.get(&PooledArc::from_ref(asset)))
            .map_or(false, |balance_map| !balance_map.is_empty())
        )
    }

    async fn has_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.contracts.get(contract)
            .and_then(|entry| entry.balances.get(asset))
            .map_or(false, |versions| versions.contains_key(&topoheight))
        )
    }

    async fn get_contract_balance_at_exact_topoheight(&self, contract: &Hash, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedContractBalance, BlockchainError> {
        self.contracts.get(contract)
            .and_then(|entry| entry.balances.get(asset))
            .and_then(|versions| versions.get(&topoheight))
            .cloned()
            .with_context(|| format!("contract balance not found for contract {}, asset {:?}, topoheight {}", contract, asset, topoheight))
            .map_err(|e| e.into())
    }

    async fn get_contract_balance_at_maximum_topoheight(&self, contract: &Hash, asset: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError> {
        Ok(self.contracts.get(contract)
            .and_then(|entry| entry.balances.get(asset))
            .and_then(|versions| versions.range(..=maximum_topoheight).next_back())
            .map(|(t, b)| (*t, b.clone()))
        )
    }

    async fn get_last_topoheight_for_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.contracts.get(contract)
            .and_then(|entry| entry.balances.get(asset))
            .and_then(|versions| versions.keys().next_back())
            .copied()
        )
    }

    async fn get_last_contract_balance(&self, contract: &Hash, asset: &Hash) -> Result<(TopoHeight, VersionedContractBalance), BlockchainError> {
        self.contracts.get(contract)
            .and_then(|entry| entry.balances.get(asset))
            .and_then(|versions| versions.iter().next_back())
            .map(|(t, b)| (*t, b.clone()))
            .with_context(|| format!("last contract balance not found for contract {:?}, asset {}", contract, asset))
            .map_err(|e| e.into())
    }

    async fn get_contract_assets_for<'a>(&'a self, contract: &'a Hash) -> Result<impl Iterator<Item = Result<Hash, BlockchainError>> + 'a, BlockchainError> {
        Ok(self.contracts.get(contract)
            .map(|entry| entry.balances.keys().map(|k| Ok(k.as_ref().clone())))
            .into_iter()
            .flatten()
        )
    }

    async fn set_last_contract_balance_to(&mut self, contract: &Hash, asset: &Hash, topoheight: TopoHeight, balance: VersionedContractBalance) -> Result<(), BlockchainError> {
        self.contracts.entry(PooledArc::from_ref(contract))
            .or_default()
            .balances
            .entry(PooledArc::from_ref(asset))
            .or_default()
            .insert(topoheight, balance);

        Ok(())
    }
}
