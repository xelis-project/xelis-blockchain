use pooled_arc::PooledArc;
use async_trait::async_trait;
use anyhow::Context;
use xelis_common::{
    account::VersionedNonce,
    block::TopoHeight,
    crypto::PublicKey,
};
use crate::core::{
    error::BlockchainError,
    storage::{NetworkProvider, NonceProvider},
};
use super::super::MemoryStorage;

#[async_trait]
impl NonceProvider for MemoryStorage {
    async fn has_nonce(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        Ok(self.accounts.get(key).map_or(false, |acc| !acc.nonces.is_empty()))
    }

    async fn has_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.accounts.get(key).map_or(false, |acc| acc.nonces.contains_key(&topoheight)))
    }

    async fn get_last_topoheight_for_nonce(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        self.accounts.get(key)
        .and_then(|acc| acc.nonces.last_key_value().map(|(topo, _)| *topo))
        .with_context(|| format!("Last topoheight for nonce not found for account {}",  key.as_address(self.is_mainnet())))
        .map_err(|e| e.into())
    }

    async fn get_last_nonce(&self, key: &PublicKey) -> Result<(TopoHeight, VersionedNonce), BlockchainError> {
        self.accounts.get(key)
            .and_then(|acc| acc.nonces.last_key_value().map(|(topo, nonce)| (*topo, nonce.clone())))
            .with_context(|| format!("Last nonce not found for account {}", key.as_address(self.is_mainnet())))
            .map_err(|e| e.into())
    }

    async fn get_nonce_at_exact_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<VersionedNonce, BlockchainError> {
        self.accounts.get(key)
            .and_then(|acc| acc.nonces.get(&topoheight).cloned())
            .with_context(|| format!("Nonce not found for account {}, topoheight {}", key.as_address(self.is_mainnet()), topoheight))
            .map_err(|e| e.into())
    }

    async fn get_nonce_at_maximum_topoheight(&self, key: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedNonce)>, BlockchainError> {
        Ok(self.accounts.get(key)
            .and_then(|acc| acc.nonces.range(..=maximum_topoheight)
                .next_back()
                .map(|(&topo, nonce)| (topo, nonce.clone()))
            )
        )
    }

    async fn set_last_nonce_to(&mut self, key: &PublicKey, topoheight: TopoHeight, nonce: &VersionedNonce) -> Result<(), BlockchainError> {
        let shared_key = PooledArc::from_ref(key);
        self.accounts.entry(shared_key)
            .or_default()
            .nonces
            .insert(topoheight, nonce.clone());

        Ok(())
    }
}
