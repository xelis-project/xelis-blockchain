use async_trait::async_trait;
use futures::TryStreamExt;
use xelis_common::{
    account::{CiphertextCache, VersionedBalance, VersionedNonce},
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
    mempool::Mempool,
    state::{FeeProvider, search_versioned_balance_for_reference},
    storage::{Storage, VersionedContractBalance, VersionedContractModule, VersionedSupply},
};
use super::{ReferenceProvider, TxVerificationProvider, ChainStateProvider};

/// Account-state provider that checks the mempool cache before falling back to storage.
/// Used during mempool TX validation.
pub struct MempoolProvider<'a, S: Storage> {
    pub mempool: &'a Mempool,
    pub storage: &'a S,
}

#[async_trait]
impl<'a, S: Storage> FeeProvider for MempoolProvider<'a, S> {
    #[inline(always)]
    async fn is_account_registered(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        self.storage.is_account_registered_for_topoheight(key, topoheight).await
    }

    #[inline(always)]
    fn is_mainnet(&self) -> bool {
        self.storage.is_mainnet()
    }
}

#[async_trait]
impl<'a, S: Storage> ReferenceProvider for MempoolProvider<'a, S> {
    #[inline(always)]
    async fn is_block_topological_ordered(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.storage.is_block_topological_ordered(hash).await
    }

    #[inline(always)]
    async fn get_topo_height_for_hash(&self, hash: &Hash) -> Result<TopoHeight, BlockchainError> {
        self.storage.get_topo_height_for_hash(hash).await
    }

    #[inline(always)]
    async fn get_pruned_topoheight(&self) -> Result<Option<TopoHeight>, BlockchainError> {
        self.storage.get_pruned_topoheight().await
    }
}

#[async_trait]
impl<'a, S: Storage> TxVerificationProvider for MempoolProvider<'a, S> {
    #[inline(always)]
    async fn has_block_with_hash(&self, hash: &Hash) -> Result<bool, BlockchainError> {
        self.storage.has_block_with_hash(hash).await
    }

    #[inline(always)]
    async fn get_height_for_block_hash(&self, hash: &Hash) -> Result<u64, BlockchainError> {
        self.storage.get_height_for_block_hash(hash).await
    }

    #[inline(always)]
    async fn get_block_header_by_hash(&self, hash: &Hash) -> Result<Immutable<BlockHeader>, BlockchainError> {
        self.storage.get_block_header_by_hash(hash).await
    }

    #[inline(always)]
    async fn get_output_balance_in_range(
        &self,
        key: &PublicKey,
        asset: &Hash,
        min_topoheight: TopoHeight,
        max_topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        self.storage.get_output_balance_in_range(key, asset, min_topoheight, max_topoheight).await
    }
}

#[async_trait]
impl<'a, S: Storage> ChainStateProvider for MempoolProvider<'a, S> {
    async fn get_account_state(
        &self,
        key: &PublicKey,
        topoheight: TopoHeight,
    ) -> Result<(VersionedNonce, Option<(VersionedState, Option<MultiSigPayload>)>), BlockchainError> {
        // If the mempool has a pending cache for this key, use it
        if let Some(cache) = self.mempool.get_cache_for(key) {
            let nonce = VersionedNonce::new(cache.get_next_nonce(), None);
            let multisig = cache.get_multisig().as_ref().map(|m| (VersionedState::New, Some(m.clone())));

            return Ok((nonce, multisig));
        }

        self.storage.get_account_state(key, topoheight).await
    }

    async fn get_sender_balance(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
        reference: &Reference,
    ) -> Result<(bool, bool, VersionedBalance), BlockchainError> {
        if let Some(ct) = self.mempool.get_cache_for(key)
            .and_then(|cache| cache.get_balances().get(asset).cloned())
        {
            let version = VersionedBalance::new(CiphertextCache::Decompressed(None, ct), None);
            return Ok((false, false, version));
        }

        search_versioned_balance_for_reference(self.storage, key, asset, topoheight, reference, true).await
    }

    #[inline(always)]
    async fn get_new_versioned_balance_for_key(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<VersionedBalance, BlockchainError> {
        self.storage.get_new_versioned_balance_for_key(key, asset, topoheight).await
    }

    #[inline(always)]
    async fn get_contract_module<'b>(
        &self,
        contract: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedContractModule<'b>)>, BlockchainError> {
        self.storage.get_contract_module(contract, topoheight).await
    }

    #[inline(always)]
    async fn get_contract_balance_at_maximum_topoheight(
        &self,
        contract: &Hash,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedContractBalance)>, BlockchainError> {
        self.storage.get_contract_balance_at_maximum_topoheight(contract, asset, topoheight).await
    }

    #[inline(always)]
    async fn get_asset_at_maximum_topoheight(
        &self,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedAssetData)>, BlockchainError> {
        self.storage.get_asset_at_maximum_topoheight(asset, topoheight).await
    }

    #[inline(always)]
    async fn get_circulating_supply_for_asset_at_maximum_topoheight(
        &self,
        asset: &Hash,
        topoheight: TopoHeight,
    ) -> Result<Option<(TopoHeight, VersionedSupply)>, BlockchainError> {
        self.storage.get_circulating_supply_for_asset_at_maximum_topoheight(asset, topoheight).await
    }

    #[inline(always)]
    async fn get_event_callbacks_available_at_maximum_topoheight(
        &self,
        contract: &Hash,
        event_id: u64,
        topoheight: TopoHeight,
    ) -> Result<Vec<(Hash, EventCallbackRegistration)>, BlockchainError> {
        self.storage.get_event_callbacks_available_at_maximum_topoheight(contract, event_id, topoheight)
            .await?
            .try_collect()
            .await
    }

    #[inline(always)]
    async fn get_contract_scheduled_executions_for_execution_topoheight(
        &self,
        topoheight: TopoHeight,
    ) -> Result<Vec<Hash>, BlockchainError> {
        self.storage.get_contract_scheduled_executions_for_execution_topoheight(topoheight)
            .await?
            .collect::<Result<Vec<_>, _>>()
    }

    #[inline(always)]
    async fn get_contract_scheduled_execution_at_topoheight(
        &self,
        contract: &Hash,
        topoheight: TopoHeight,
    ) -> Result<ScheduledExecution, BlockchainError> {
        self.storage.get_contract_scheduled_execution_at_topoheight(contract, topoheight).await
    }
}
