use pooled_arc::PooledArc;
use async_trait::async_trait;
use xelis_common::{
    block::TopoHeight,
    crypto::PublicKey,
};
use crate::core::{
    error::BlockchainError,
    storage::AccountProvider,
};
use super::super::MemoryStorage;

#[async_trait]
impl AccountProvider for MemoryStorage {
    async fn count_accounts(&self) -> Result<u64, BlockchainError> {
        Ok(self.accounts.len() as u64)
    }

    async fn get_account_registration_topoheight(&self, key: &PublicKey) -> Result<TopoHeight, BlockchainError> {
        self.accounts.get(key)
            .and_then(|a| a.registered_at)
            .ok_or(BlockchainError::UnknownAccount)
    }

    async fn set_account_registration_topoheight(&mut self, key: &PublicKey, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        let shared = PooledArc::from_ref(key);
        self.accounts.entry(shared)
            .or_default()
            .registered_at = Some(topoheight);

        Ok(())
    }

    async fn delete_account_for(&mut self, key: &PublicKey) -> Result<(), BlockchainError> {
        self.accounts.remove(key);
        Ok(())
    }

    async fn is_account_registered(&self, key: &PublicKey) -> Result<bool, BlockchainError> {
        Ok(self.accounts.get(key).and_then(|a| a.registered_at).is_some())
    }

    async fn is_account_registered_for_topoheight(&self, key: &PublicKey, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        Ok(self.accounts.get(key)
            .map_or(false, |a| a.registered_at.map_or(false, |t| t <= topoheight)))
    }

    async fn get_registered_keys<'a>(&'a self, minimum_topoheight: Option<TopoHeight>, maximum_topoheight: Option<TopoHeight>) -> Result<impl Iterator<Item = Result<PublicKey, BlockchainError>> + 'a, BlockchainError> {
        Ok(self.accounts.iter()
            .filter(move |(_, account)| {
                let Some(registered_at) = account.registered_at else {
                    return false;
                };
                if minimum_topoheight.is_some_and(|v| registered_at < v) {
                    return false;
                }
                if maximum_topoheight.is_some_and(|v| registered_at > v) {
                    return false;
                }
                true
            })
            .map(|(key, _)| Ok(key.as_ref().clone()))
        )
    }

    async fn has_key_updated_in_range(&self, key: &PublicKey, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        // Check balance pointers for this account
        let updated = self.accounts
                .get(key)
                .map_or(false, |acc|
                    acc.nonces.range(minimum_topoheight..=maximum_topoheight).next().is_some() ||  acc.balances.values()
                        .map(|versions| versions.range(minimum_topoheight..=maximum_topoheight))
                        .flatten()
                        .next()
                        .is_some()
                );

        Ok(updated)
    }
}
