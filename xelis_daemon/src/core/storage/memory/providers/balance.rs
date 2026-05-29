use pooled_arc::PooledArc;
use async_trait::async_trait;
use anyhow::Context;
use xelis_common::{
    account::{AccountSummary, Balance, VersionedBalance},
    block::TopoHeight,
    crypto::{Hash, PublicKey},
};
use crate::core::{
    error::BlockchainError,
    storage::BalanceProvider,
};
use super::super::MemoryStorage;

#[async_trait]
impl BalanceProvider for MemoryStorage {
    async fn has_balance_for(&self, key: &PublicKey, asset: &Hash) -> Result<bool, BlockchainError> {
        Ok(self.accounts.get(key).and_then(|acc| acc.balances.get(asset)).is_some())
    }

    async fn has_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(
            self.accounts.get(key)
                .and_then(|acc| acc.balances.get(asset))
                .map_or(false, |versions| versions.contains_key(&topoheight))
        )
    }

    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError> {
        self.accounts.get(key)
            .and_then(|acc| acc.balances.get(asset))
            .and_then(|versions| versions.get(&topoheight))
            .cloned()
            .with_context(|| format!("Balance not found for account {:?}, asset {:?}, topoheight {}", key, asset, topoheight))
            .map_err(|e| e.into())
    }

    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        let version = self.accounts.get(key)
            .and_then(|acc| acc.balances.get(asset))
            .and_then(|versions| versions.range(..=maximum_topoheight).next_back());

        Ok(version.map(|(&topo, balance)| (topo, balance.clone())))
    }

    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<TopoHeight, BlockchainError> {
        self.accounts.get(key)
            .and_then(|acc| acc.balances.get(asset))
            .and_then(|versions| versions.keys().last().cloned())
            .with_context(|| format!("Last topoheight for balance not found for account {:?}, asset {:?}", key, asset))
            .map_err(|e| e.into())
    }

    async fn get_new_versioned_balance(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<(VersionedBalance, bool), BlockchainError> {
        match self.get_balance_at_maximum_topoheight(key, asset, topoheight).await? {
            Some((topo, mut version)) => {
                version.prepare_new(Some(topo));
                Ok((version, false))
            }
            None => Ok((VersionedBalance::zero(), true)),
        }
    }

    async fn get_output_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        self.get_output_balance_in_range(key, asset, 0, maximum_topoheight).await
    }

    async fn get_output_balance_in_range(&self, key: &PublicKey, asset: &Hash, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        let version = self.accounts.get(key)
            .and_then(|acc| acc.balances.get(asset))
            .and_then(|versions| versions.range(minimum_topoheight..=maximum_topoheight)
                .filter(|(_, balance)| balance.contains_output())
                .next_back()
            );

        Ok(version.map(|(&topo, balance)| (topo, balance.clone())))
    }

    async fn get_last_balance(&self, key: &PublicKey, asset: &Hash) -> Result<(TopoHeight, VersionedBalance), BlockchainError> {
        let version = self.accounts.get(key)
            .and_then(|acc| acc.balances.get(asset))
            .and_then(|versions| versions.last_key_value());

        version.map(|(&topo, balance)| (topo, balance.clone()))
            .with_context(|| format!("Last balance not found for account {:?}, asset {:?}", key, asset))
            .map_err(|e| e.into())
    }

    fn set_last_topoheight_for_balance(&mut self, _: &PublicKey, _: &Hash, _: TopoHeight) -> Result<(), BlockchainError> {
        Ok(())
    }

    async fn set_last_balance_to(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight, version: &VersionedBalance) -> Result<(), BlockchainError> {
        self.set_balance_at_topoheight(asset, topoheight, key, version).await
    }

    async fn set_balance_at_topoheight(&mut self, asset: &Hash, topoheight: TopoHeight, key: &PublicKey, balance: &VersionedBalance) -> Result<(), BlockchainError> {
        let shared_key = PooledArc::from_ref(key);
        let shared_asset = PooledArc::from_ref(asset);

        self.accounts.entry(shared_key)
            .or_default()
            .balances
            .entry(shared_asset)
            .or_default()
            .insert(topoheight, balance.clone());

        Ok(())
    }

    async fn get_account_summary_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<Option<AccountSummary>, BlockchainError> {
        if let Some((topo, version)) = self.get_balance_at_maximum_topoheight(key, asset, max_topoheight).await? {
            if topo < min_topoheight {
                return Ok(None);
            }

            let mut account = AccountSummary {
                output_topoheight: None,
                stable_topoheight: topo,
            };

            if version.contains_output() {
                return Ok(Some(account));
            }

            if let Some(previous) = version.get_previous_topoheight() {
                account.output_topoheight = self.get_output_balance_in_range(key, asset, min_topoheight, previous).await?
                    .map(|(t, _)| t);
            }

            return Ok(Some(account));
        }

        Ok(None)
    }

    async fn get_spendable_balances_for(&self, key: &PublicKey, asset: &Hash, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight, maximum: usize) -> Result<(Vec<Balance>, Option<TopoHeight>), BlockchainError> {
        let mut balances = Vec::new();

        let mut iter = self.accounts.get(key)
            .and_then(|acc| acc.balances.get(asset))
            .map(|versions| versions.range(minimum_topoheight..=maximum_topoheight))
            .with_context(|| format!("Spendable balances not found for account {:?}, asset {:?}", key, asset))?;

        let mut next_topo = None;
        while let Some((&topo, version)) = iter.next_back().filter(|_| balances.len() < maximum) {
            let version = version.clone();
            let has_output = version.contains_output();

            next_topo = version.get_previous_topoheight();
            balances.push(version.as_balance(topo));

            if has_output {
                next_topo = None;
                break;
            }
        }

        Ok((balances, next_topo))
    }
}
