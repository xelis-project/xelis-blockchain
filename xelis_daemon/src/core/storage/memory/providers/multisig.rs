use std::borrow::Cow;

use pooled_arc::PooledArc;
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
    versioned::Versioned,
};
use crate::core::{
    error::BlockchainError,
    storage::{MultiSigProvider, VersionedMultiSig},
};
use super::super::MemoryStorage;

#[async_trait]
impl MultiSigProvider for MemoryStorage {
    async fn get_last_topoheight_for_multisig(&self, key: &PublicKey) -> Result<Option<TopoHeight>, BlockchainError> {
        Ok(self.accounts.get(key)
            .and_then(|acc| acc.multisig.last_key_value().map(|(topo, _)| *topo))
        )
    }

    async fn get_multisig_at_topoheight_for<'a>(&'a self, key: &PublicKey, topoheight: TopoHeight) -> Result<VersionedMultiSig<'a>, BlockchainError> {
        self.accounts.get(key)
            .and_then(|acc| acc.multisig.get(&topoheight).cloned())
            .ok_or(BlockchainError::MultisigNotFound)
    }

    async fn get_multisig_at_maximum_topoheight_for<'a>(&'a self, account: &PublicKey, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedMultiSig<'a>)>, BlockchainError> {
        Ok(self.accounts.get(account)
            .and_then(|acc| acc.multisig.range(..=maximum_topoheight)
                .next_back()
                .map(|(&topo, multisig)| (topo, multisig.clone()))
            )
        )
    }

    async fn has_multisig(&self, account: &PublicKey) -> Result<bool, BlockchainError> {
        Ok(self.accounts.get(account)
            .and_then(|acc| acc.multisig.last_key_value())
            .is_some_and(|(_, version)| version.get().is_some())
        )
    }

    async fn has_multisig_at_exact_topoheight(&self, account: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.accounts.get(account)
            .map_or(false, |acc| acc.multisig.contains_key(&topoheight))
        )
    }

    async fn set_last_multisig_to<'a>(&mut self, key: &PublicKey, topoheight: TopoHeight, multisig: VersionedMultiSig<'a>) -> Result<(), BlockchainError> {
        let shared_key = PooledArc::from_ref(key);
        self.accounts.entry(shared_key)
            .or_default()
            .multisig
            .insert(topoheight, Versioned::new(multisig.get().as_ref().map(|v| Cow::Owned(v.as_ref().clone())), multisig.get_previous_topoheight()));

        Ok(())
    }
}
