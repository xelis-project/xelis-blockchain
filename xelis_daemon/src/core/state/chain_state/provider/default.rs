use async_trait::async_trait;
use futures::TryStreamExt;
use xelis_common::{
    account::{VersionedBalance, VersionedNonce},
    asset::VersionedAssetData,
    block::{BlockHeader, TopoHeight},
    contract::{EventCallbackRegistration, ScheduledExecution},
    crypto::{Hash, PublicKey},
    immutable::Immutable,
    transaction::{MultiSigPayload, Reference},
    versioned::VersionedState,
};
use crate::core::{
    error::BlockchainError,
    state::search_versioned_balance_for_reference,
    storage::{Storage, VersionedContractBalance, VersionedContractModule, VersionedSupply},
};
use super::{ReferenceProvider, TxVerificationProvider, ChainStateProvider};

#[async_trait]
impl<S: Storage> ReferenceProvider for S {
    #[inline(always)]
    async fn is_block_topological_ordered(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.is_block_topological_ordered(hash).await
    }

    #[inline(always)]
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        self.get_topo_height_for_hash(hash).await
    }

    #[inline(always)]
    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError> {
        self.get_pruned_topoheight().await
    }
}

#[async_trait]
impl<S: Storage> TxVerificationProvider for S {
    #[inline(always)]
    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.has_block_with_hash(hash).await
    }

    #[inline(always)]
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        self.get_height_for_block_hash(hash).await
    }

    #[inline(always)]
    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Immutable<BlockHeader>, BlockchainError> {
        self.get_block_header_by_hash(hash).await
    }

    #[inline(always)]
    async fn get_output_balance_in_range(
        &self,
        key: &PublicKey,
        asset: &Hash,
        min_topoheight: TopoHeight,
        max_topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        self.get_output_balance_in_range(key, asset, min_topoheight, max_topoheight).await
    }
}

#[async_trait]
impl<S: Storage> ChainStateProvider for S {
    async fn get_account_state(
        &self,
        key: &PublicKey,
        topoheight: TopoHeight,
    ) -> Result<(VersionedNonce, Option<(VersionedState, Option<MultiSigPayload>)>), BlockchainError> {
        let (topo, mut version) = self
            .get_nonce_at_maximum_topoheight(key, topoheight).await?
            .ok_or_else(|| BlockchainError::AccountNotFound(key.as_address(self.is_mainnet())))?;

        version.set_previous_topoheight(Some(topo));

        let multisig = self
            .get_multisig_at_maximum_topoheight_for(key, topoheight).await?
            .map(|(topo, multisig)| {
                multisig.take().map(|m| (VersionedState::FetchedAt(topo), Some(m.into_owned())))
            })
            .flatten();

        Ok((version, multisig))
    }

    #[inline(always)]
    async fn get_sender_balance(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
        reference: &Reference,
    ) -> Result<(bool, bool, VersionedBalance), BlockchainError> {
        search_versioned_balance_for_reference(self, key, asset, topoheight, reference, true).await
    }

    #[inline(always)]
    async fn get_new_versioned_balance_for_key(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<VersionedBalance, BlockchainError> {
        self.get_new_versioned_balance(key, asset, topoheight).await
            .map(|(version, _)| version)
    }

    #[inline(always)]
    async fn get_contract_module<'a>(
        &self,
        contract: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedContractModule<'a>)>, BlockchainError> {
        self.get_contract_at_maximum_topoheight_for(contract, topoheight).await
    }

    #[inline(always)]
    async fn get_contract_balance_at_maximum_topoheight(
        &self,
        contract: &Hash,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError> {
        self.get_contract_balance_at_maximum_topoheight(contract, asset, topoheight).await
    }

    #[inline(always)]
    async fn get_asset_at_maximum_topoheight(
        &self,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedAssetData)>, BlockchainError> {
        self.get_asset_at_maximum_topoheight(asset, topoheight).await
    }

    #[inline(always)]
    async fn get_circulating_supply_for_asset_at_maximum_topoheight(
        &self,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError> {
        self.get_circulating_supply_for_asset_at_maximum_topoheight(asset, topoheight).await
    }

    #[inline(always)]
    async fn get_event_callbacks_available_at_maximum_topoheight(
        &self,
        contract: &Hash,
        event_id: u64,
        topoheight: TopoHeight,
    ) -> Result<Vec<(Hash, EventCallbackRegistration)>, BlockchainError> {
        self.get_event_callbacks_available_at_maximum_topoheight(contract, event_id, topoheight)
            .await?
            .try_collect()
            .await
    }

    #[inline(always)]
    async fn get_contract_scheduled_executions_for_execution_topoheight(
        &self,
        topoheight: TopoHeight,
    ) -> Result<Vec<Hash>, BlockchainError> {
        self.get_contract_scheduled_executions_for_execution_topoheight(topoheight).await
            .and_then(Iterator::collect)
    }

    #[inline(always)]
    async fn get_contract_scheduled_execution_at_topoheight(
        &self,
        contract: &Hash,
        topoheight: TopoHeight,
    ) -> Result<ScheduledExecution, BlockchainError> {
        self.get_contract_scheduled_execution_at_topoheight(contract, topoheight).await
    }
}
