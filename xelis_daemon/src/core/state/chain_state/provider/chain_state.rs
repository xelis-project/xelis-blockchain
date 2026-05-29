use async_trait::async_trait;
use xelis_common::{
    account::{VersionedBalance, VersionedNonce},
    asset::VersionedAssetData,
    block::TopoHeight,
    contract::{EventCallbackRegistration, ScheduledExecution},
    crypto::{Hash, PublicKey},
    transaction::{MultiSigPayload, Reference},
    versioned::VersionedState,
};
use crate::core::{
    error::BlockchainError,
    storage::{VersionedContractBalance, VersionedContractModule, VersionedSupply},
};
use super::TxVerificationProvider;

/// Abstracts the chain state lookups performed by [`ChainState`].
#[async_trait]
pub trait ChainStateProvider: TxVerificationProvider {
    /// Fetch the initial nonce and multisig state for a sender account.
    async fn get_account_state(
        &self,
        key: &PublicKey,
        topoheight: TopoHeight,
    ) -> Result<(VersionedNonce, Option<(VersionedState, Option<MultiSigPayload>)>), BlockchainError>;

    /// Return the initial sender balance for an asset.
    /// Implementations may serve this from a cache (e.g. mempool) before falling back to storage.
    async fn get_sender_balance(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
        reference: &Reference,
    ) -> Result<(bool, bool, VersionedBalance), BlockchainError>;

    /// Get a new versioned balance for a key and asset.
    async fn get_new_versioned_balance_for_key(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<VersionedBalance, BlockchainError>;

    /// Fetch a contract module for a given contract and topoheight.
    async fn get_contract_module<'a>(
        &self,
        contract: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedContractModule<'a>)>, BlockchainError>;

    /// Get the contract balance at or below the given topoheight.
    async fn get_contract_balance_at_maximum_topoheight(
        &self,
        contract: &Hash,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError>;

    /// Get an asset's versioned data at or below the given topoheight.
    async fn get_asset_at_maximum_topoheight(
        &self,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedAssetData)>, BlockchainError>;

    /// Get the circulating supply for an asset at or below the given topoheight.
    async fn get_circulating_supply_for_asset_at_maximum_topoheight(
        &self,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError>;

    /// Get all active event callbacks for a contract event at or below the given topoheight.
    async fn get_event_callbacks_available_at_maximum_topoheight(
        &self,
        contract: &Hash,
        event_id: u64,
        topoheight: TopoHeight,
    ) -> Result<Vec<(Hash, EventCallbackRegistration)>, BlockchainError>;

    /// Get the hashes of all scheduled executions planned for the given topoheight.
    async fn get_contract_scheduled_executions_for_execution_topoheight(
        &self,
        topoheight: TopoHeight,
    ) -> Result<Vec<Hash>, BlockchainError>;

    /// Get a specific scheduled execution registered for the given contract and topoheight.
    async fn get_contract_scheduled_execution_at_topoheight(
        &self,
        contract: &Hash,
        topoheight: TopoHeight,
    ) -> Result<ScheduledExecution, BlockchainError>;
}
