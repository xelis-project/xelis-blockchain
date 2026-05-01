use async_trait::async_trait;
use xelis_common::{
    account::{CiphertextCache, VersionedBalance, VersionedNonce},
    block::TopoHeight,
    crypto::{Hash, PublicKey},
    transaction::{MultiSigPayload, Reference},
    versioned::VersionedState,
};
use crate::core::{
    error::BlockchainError,
    mempool::Mempool,
    state::search_versioned_balance_for_reference,
    storage::Storage,
};

/// Abstracts the account-state lookups performed by [`ChainState`].
///
/// Two built-in implementations are provided:
/// - Blanket impl on `S: Storage` — reads directly from storage (block application)
/// - [`MempoolProvider`] — checks the in-memory mempool cache first,
///   then falls back to storage (mempool TX validation)
#[async_trait]
pub trait ChainStateProvider: Send + Sync {
    type Storage: Storage;
    fn storage(&self) -> &Self::Storage;
    
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
}

#[async_trait]
impl<S: Storage> ChainStateProvider for S {
    type Storage = S;

    #[inline(always)]
    fn storage(&self) -> &S {
        self
    }

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

    async fn get_sender_balance(
        &self,
        key: &PublicKey,
        asset: &Hash,
        topoheight: TopoHeight,
        reference: &Reference,
    ) -> Result<(bool, bool, VersionedBalance), BlockchainError> {
        search_versioned_balance_for_reference(self, key, asset, topoheight, reference, true).await
    }
}

/// Account-state provider that checks the mempool cache before falling back to storage.
/// Used during mempool TX validation.
pub struct MempoolProvider<'a, S: Storage> {
    pub mempool: &'a Mempool,
    pub storage: &'a S,
}

#[async_trait]
impl<'a, S: Storage> ChainStateProvider for MempoolProvider<'a, S> {
    type Storage = S;

    #[inline(always)]
    fn storage(&self) -> &Self::Storage {
        self.storage
    }

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
}
