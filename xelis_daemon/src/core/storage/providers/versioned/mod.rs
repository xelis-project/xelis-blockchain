mod balance;
mod contract;
mod multisig;
mod nonce;
mod registrations;
mod asset;
mod cache;
mod dag_order;
mod asset_supply;

use async_trait::async_trait;
use log::debug;
use xelis_common::block::TopoHeight;
use crate::core::error::BlockchainError;

pub use balance::*;
pub use contract::*;
pub use multisig::*;
pub use nonce::*;
pub use registrations::*;
pub use asset::*;
pub use cache::*;
pub use dag_order::*;
pub use asset_supply::*;

// Every versioned key should start with the topoheight in order to be able to delete them easily
#[async_trait]
pub trait VersionedProvider:
    VersionedBalanceProvider
    + VersionedNonceProvider
    + VersionedMultiSigProvider
    + VersionedContractProvider
    + VersionedRegistrationsProvider
    + VersionedAssetProvider
    + VersionedAssetsCirculatingSupplyProvider
    + VersionedCacheProvider
    + VersionedDagOrderProvider {

    // Delete versioned data at topoheight
    async fn delete_versioned_data_at_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        debug!("delete versioned data at topoheight {}", topoheight);
        self.delete_versioned_balances_at_topoheight(topoheight).await?;
        self.delete_versioned_nonces_at_topoheight(topoheight).await?;
        self.delete_versioned_multisigs_at_topoheight(topoheight).await?;
        self.delete_versioned_registrations_at_topoheight(topoheight).await?;

        self.delete_versioned_contracts_at_topoheight(topoheight).await?;
        self.delete_versioned_contract_data_at_topoheight(topoheight).await?;
        self.delete_versioned_contract_balances_at_topoheight(topoheight).await?;
        self.delete_scheduled_executions_at_topoheight(topoheight).await?;

        self.delete_versioned_assets_supply_at_topoheight(topoheight).await?;
        self.delete_dag_order_at_topoheight(topoheight).await?;

        // Special case: because we inject it directly into the chain at startup
        if topoheight > 0 {
            self.delete_versioned_assets_at_topoheight(topoheight).await?;
        }

        Ok(())
    }

    // Delete versioned data below topoheight
    // Special case for versioned balances:
    // Because users can link a TX to an old versioned balance, we need to keep track of them until the latest spent version
    async fn delete_versioned_data_below_topoheight(&mut self, topoheight: TopoHeight, keep_last: bool) -> Result<(), BlockchainError> {
        debug!("delete versioned data below topoheight {}", topoheight);
        self.delete_versioned_balances_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_nonces_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_multisigs_below_topoheight(topoheight, keep_last).await?;
        // no deletions of registrations below topoheight, we keep them marked

        self.delete_versioned_contracts_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_contract_data_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_contract_balances_below_topoheight(topoheight, keep_last).await?;
        self.delete_scheduled_executions_below_topoheight(topoheight).await?;

        self.delete_versioned_assets_supply_below_topoheight(topoheight, keep_last).await?;
        self.delete_versioned_assets_below_topoheight(topoheight, keep_last).await?;

        self.clear_versioned_data_caches().await
    }

    // Delete versioned data above topoheight
    async fn delete_versioned_data_above_topoheight(&mut self, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        debug!("delete versioned data above topoheight {}", topoheight);
        self.delete_versioned_balances_above_topoheight(topoheight).await?;
        self.delete_versioned_nonces_above_topoheight(topoheight).await?;
        self.delete_versioned_multisigs_above_topoheight(topoheight).await?;
        self.delete_versioned_registrations_above_topoheight(topoheight).await?;

        self.delete_versioned_contracts_above_topoheight(topoheight).await?;
        self.delete_versioned_contract_data_above_topoheight(topoheight).await?;
        self.delete_versioned_contract_balances_above_topoheight(topoheight).await?;
        self.delete_scheduled_executions_above_topoheight(topoheight).await?;

        self.delete_versioned_assets_supply_above_topoheight(topoheight).await?;
        self.delete_versioned_assets_above_topoheight(topoheight).await?;

        // Special case, delete hashes / topo pointers
        self.delete_dag_order_above_topoheight(topoheight).await?;

        self.clear_versioned_data_caches().await
    }
}