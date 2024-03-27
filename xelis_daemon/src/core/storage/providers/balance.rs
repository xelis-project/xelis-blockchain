use async_trait::async_trait;
use log::{trace, error};
use xelis_common::{
    account::VersionedBalance,
    crypto::{
        Hash,
        PublicKey
    },
    serializer::Serializer
};

use crate::core::{error::BlockchainError, storage::SledStorage};
use super::AssetProvider;

#[async_trait]
pub trait BalanceProvider: AssetProvider {
    // Check if a balance exists for asset and key
    async fn has_balance_for(&self, key: &PublicKey, asset: &Hash) -> Result<bool, BlockchainError>;

    // Check if a balance exists for asset and key at specific topoheight
    async fn has_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<bool, BlockchainError>;

    // Get the balance at a specific topoheight for asset and key
    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError>;

    // Get the balance under or equal topoheight requested for asset and key
    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<Option<(u64, VersionedBalance)>, BlockchainError>;

    // Get the last topoheight that the account has a balance
    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<u64, BlockchainError>;

    // Get a new versioned balance of the account, this is based on the requested topoheight
    // And is returning the versioned balance at maximum topoheight
    // Versioned balance as the previous topoheight set also based on which height it is set
    // So, if we are at topoheight 50 and we have a balance at topoheight 40, the previous topoheight will be 40
    // But also if we have a balance at topoheight 50, the previous topoheight will also be 50
    // This must be called only to create a new versioned balance for the next topoheight as it's keeping changes from the balance at same topo
    async fn get_new_versioned_balance(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError>;

    // Search the highest balance where we have a outgoing TX
    async fn get_output_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<Option<(u64, VersionedBalance)>, BlockchainError>;

    // Get the last balance of the account, this is based on the last topoheight (pointer) available
    async fn get_last_balance(&self, key: &PublicKey, asset: &Hash) -> Result<(u64, VersionedBalance), BlockchainError>;

    // Get the asset versioned balances for multiple keys
    async fn get_versioned_balances<'a, I: Iterator<Item = &'a PublicKey> + Send>(&self, asset: &Hash, keys: I, maximum_topoheight: u64) -> Result<Vec<Option<VersionedBalance>>, BlockchainError>;

    // Set the last topoheight for this asset and key to the requested topoheight
    fn set_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<(), BlockchainError>;

    // Set the last balance of the account, update the last topoheight pointer for asset and key
    // This is same as `set_last_topoheight_for_balance` but will also update the versioned balance
    async fn set_last_balance_to(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64, version: &VersionedBalance) -> Result<(), BlockchainError>;

    // Set the balance at specific topoheight for asset and key
    async fn set_balance_at_topoheight(&mut self, asset: &Hash, topoheight: u64, key: &PublicKey, balance: &VersionedBalance) -> Result<(), BlockchainError>;

    // Delete the balance at specific topoheight for asset and key
    async fn delete_balance_at_topoheight(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError>;

    // Delete the last topoheight for asset and key
    // This will only remove the pointer, not the version itself
    fn delete_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash) -> Result<(), BlockchainError>;
}

impl SledStorage {
    // Generate a key including the key and its asset
    // It is used to store/retrieve the highest topoheight version available
    pub fn get_balance_key_for(&self, key: &PublicKey, asset: &Hash) -> [u8; 64] {
        trace!("get balance {} key for {}", asset, key.as_address(self.is_mainnet()));
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(key.as_bytes());
        bytes[32..64].copy_from_slice(asset.as_bytes());
        bytes
    }

    // Versioned key is a 72 bytes key with topoheight, key, assets bytes
    pub fn get_versioned_balance_key(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> [u8; 72] {
        trace!("get versioned balance {} key at {} for {}", asset, topoheight, key.as_address(self.is_mainnet()));
        let mut bytes = [0; 72];
        bytes[0..8].copy_from_slice(&topoheight.to_be_bytes());
        bytes[8..40].copy_from_slice(key.as_bytes());
        bytes[40..72].copy_from_slice(asset.as_bytes());

        bytes
    }

    async fn has_balance_internal(&self, key: &[u8; 64]) -> Result<bool, BlockchainError> {
        trace!("has balance internal");
        Ok(self.balances.contains_key(key)?)
    }

}

#[async_trait]
impl BalanceProvider for SledStorage {
    // Check if a balance exists for asset and key
    async fn has_balance_for(&self, key: &PublicKey, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("has balance {} for {}", asset, key.as_address(self.is_mainnet()));
        if !self.has_asset(asset).await? {
            return Err(BlockchainError::AssetNotFound(asset.clone()))
        }

        self.has_balance_internal(&self.get_balance_key_for(key, asset)).await
    }

    // returns the highest topoheight where a balance changes happened
    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<u64, BlockchainError> {
        trace!("get last topoheight for balance {} for {}", asset, key.as_address(self.is_mainnet()));
        let key = self.get_balance_key_for(key, asset);
        if !self.has_balance_internal(&key).await? {
            return Ok(0)
        }

        self.get_cacheable_data(&self.balances, &None, &key).await
    }

    // set in storage the new top topoheight (the most up-to-date versioned balance)
    fn set_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<(), BlockchainError> {
        trace!("set last topoheight to {} for balance {} for {}", topoheight, asset, key.as_address(self.is_mainnet()));
        let key = self.get_balance_key_for(key, asset);
        self.balances.insert(&key, &topoheight.to_be_bytes())?;
        Ok(())
    }

    // get the balance at a specific topoheight
    // if there is no balance change at this topoheight just return an error
    async fn has_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<bool, BlockchainError> {
        trace!("has balance {} for {} at exact topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        // check first that this address has balance, if no returns
        if !self.has_balance_for(key, asset).await? {
            return Ok(false)
        }

        let key = self.get_versioned_balance_key(key, asset, topoheight);
        self.contains_data::<_, ()>(&self.versioned_balances, &None, &key).await
    }

    // get the balance at a specific topoheight
    // if there is no balance change at this topoheight just return an error
    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError> {
        trace!("get balance {} for {} at exact topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        // check first that this address has balance, if no returns
        if !self.has_balance_at_exact_topoheight(key, asset, topoheight).await? {
            trace!("No balance {} found for {} at exact topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
            return Err(BlockchainError::NoBalanceChanges(key.as_address(self.is_mainnet()), topoheight, asset.clone()))
        }

        let disk_key = self.get_versioned_balance_key(key, asset, topoheight);
        self.get_cacheable_data(&self.versioned_balances, &None, &disk_key).await.map_err(|_| BlockchainError::NoBalanceChanges(key.as_address(self.is_mainnet()), topoheight, asset.clone()))
    }

    // delete the last topoheight registered for this key
    // it can happens when rewinding chain and we don't have any changes (no transaction in/out) for this key
    // because all versioned balances got deleted
    fn delete_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash) -> Result<(), BlockchainError> {
        trace!("delete last topoheight balance {} for {}", asset, key.as_address(self.is_mainnet()));
        let key = self.get_balance_key_for(key, asset);
        self.balances.remove(&key)?;
        Ok(())
    }

    // get the latest balance at maximum specified topoheight
    // when a DAG re-ordering happens, we need to select the right balance and not the last one
    // returns None if the key has no balances for this asset
    // Maximum topoheight is inclusive
    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<Option<(u64, VersionedBalance)>, BlockchainError> {
        trace!("get balance {} for {} at maximum topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        // check first that this address has balance for this asset, if no returns None
        if !self.has_balance_for(key, asset).await? {
            trace!("No balance {} found for {} at maximum topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
            return Ok(None)
        }

        // Fast path: if the balance is at exact topoheight, return it
        if self.has_balance_at_exact_topoheight(key, asset, topoheight).await? {
            trace!("Balance version found at exact (maximum) topoheight {}", topoheight);
            return Ok(Some((topoheight, self.get_balance_at_exact_topoheight(key, asset, topoheight).await?)))
        }

        let (topo, mut version) = self.get_last_balance(key, asset).await?;
        trace!("Last version balance {} for {} is at topoheight {}", asset, key.as_address(self.is_mainnet()), topo);
        // if it's the latest and its under the maximum topoheight
        if topo <= topoheight {
            trace!("Last version balance (valid) found at {} (maximum topoheight = {})", topo, topoheight);
            return Ok(Some((topo, version)))
        }

        // otherwise, we have to go through the whole chain
        while let Some(previous) = version.get_previous_topoheight() {
            let previous_version = self.get_balance_at_exact_topoheight(key, asset, previous).await?;
            trace!("previous version {}", previous);
            if previous <= topoheight {
                trace!("Highest version balance found at {} (maximum topoheight = {})", topo, topoheight);
                return Ok(Some((previous, previous_version)))
            }

            if let Some(value) = previous_version.get_previous_topoheight() {
                if value > previous {
                    error!("FATAL ERROR: Previous topoheight ({}) should not be higher than current version ({})!", value, previous);
                    return Err(BlockchainError::Unknown)
                }
            }
            version = previous_version;
        }

        Ok(None)
    }

    // delete versioned balances for this topoheight
    async fn delete_balance_at_topoheight(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError> {
        trace!("delete balance {} for {} at topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        let disk_key = self.get_versioned_balance_key(key, asset, topoheight);
        self.delete_cacheable_data(&self.versioned_balances, &None, &disk_key).await.map_err(|_| BlockchainError::NoBalanceChanges(key.as_address(self.is_mainnet()), topoheight, asset.clone()))
    }

    // returns a new versioned balance with already-set previous topoheight
    // Topoheight is the new topoheight for the versioned balance,
    // We create a new versioned balance by taking the previous version and setting it as previous topoheight
    async fn get_new_versioned_balance(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<VersionedBalance, BlockchainError> {
        trace!("get new versioned balance {} for {} at {}", asset, key.as_address(self.is_mainnet()), topoheight);

        let version = match self.get_balance_at_maximum_topoheight(key, asset, topoheight).await? {
            Some((topo, mut version)) => {
                trace!("new versioned balance (balance at maximum topoheight) topo: {}, previous: {:?}, requested topo: {}", topo, version.get_previous_topoheight(), topo);
                // Mark it as clean
                version.prepare_new(Some(topo));
                version
            },
            // if its the first balance, then we return a zero balance
            None => VersionedBalance::zero()
        };

        Ok(version)
    }

    async fn get_output_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: u64) -> Result<Option<(u64, VersionedBalance)>, BlockchainError> {
        trace!("get output balance {} for {} at maximum topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        if let Some((topo, version)) = self.get_balance_at_maximum_topoheight(key, asset, topoheight).await? {
            if version.contains_output() {
                return Ok(Some((topo, version)))
            }

            // TODO: maybe we can optimize this by storing the last output balance topoheight as pointer
            let mut previous = version.get_previous_topoheight();
            while let Some(topo) = previous {
                let previous_version = self.get_balance_at_exact_topoheight(key, asset, topo).await?;
                if previous_version.contains_output() {
                    return Ok(Some((topo, previous_version)))
                }

                previous = previous_version.get_previous_topoheight();
            }
        }

        Ok(None)
    }

    // save a new versioned balance in storage and update the pointer
    async fn set_last_balance_to(&mut self, key: &PublicKey, asset: &Hash, topoheight: u64, version: &VersionedBalance) -> Result<(), BlockchainError> {
        trace!("set balance {} for {} to topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        self.set_balance_at_topoheight(asset, topoheight, key, &version).await?;
        self.set_last_topoheight_for_balance(key, asset, topoheight)?;
        Ok(())
    }

    // get the last version of balance and returns topoheight
    async fn get_last_balance(&self, key: &PublicKey, asset: &Hash) -> Result<(u64, VersionedBalance), BlockchainError> {
        trace!("get last balance {} for {}", asset, key.as_address(self.is_mainnet()));
        if !self.has_balance_for(key, asset).await? {
            trace!("No balance {} found for {}", asset, key.as_address(self.is_mainnet()));
            return Err(BlockchainError::NoBalance(key.as_address(self.is_mainnet())))
        }

        let topoheight = self.get_cacheable_data(&self.balances, &None, &self.get_balance_key_for(key, asset)).await?;
        let version = self.get_balance_at_exact_topoheight(key, asset, topoheight).await?;
        Ok((topoheight, version))
    }

    async fn get_versioned_balances<'a, I: Iterator<Item = &'a PublicKey> + Send>(&self, asset: &Hash, keys: I, maximum_topoheight: u64) -> Result<Vec<Option<VersionedBalance>>, BlockchainError> {
        trace!("get balances for asset {} at maximum topoheight {}", asset, maximum_topoheight);
        let mut balances = Vec::new();
        for key in keys {
            if self.has_balance_for(key, asset).await? {
                let res = self.get_balance_at_maximum_topoheight(key, asset, maximum_topoheight).await?
                    .map(|(_, v)| v);
                balances.push(res);
            } else {
                balances.push(None);
            }
        }
        Ok(balances)
    }

    // save the asset balance at specific topoheight
    async fn set_balance_at_topoheight(&mut self, asset: &Hash, topoheight: u64, key: &PublicKey, balance: &VersionedBalance) -> Result<(), BlockchainError> {
        trace!("set balance {} at topoheight {} for {}", asset, topoheight, key.as_address(self.is_mainnet()));
        let key = self.get_versioned_balance_key(key, asset, topoheight);
        self.versioned_balances.insert(key, balance.to_bytes())?;
        Ok(())
    }
}