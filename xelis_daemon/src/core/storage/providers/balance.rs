use async_trait::async_trait;
use log::trace;
use xelis_common::{
    account::{
        AccountSummary,
        Balance,
        BalanceType,
        VersionedBalance
    },
    block::TopoHeight,
    crypto::{
        Hash,
        PublicKey
    },
    serializer::{Serializer, DEFAULT_MAX_ITEMS}
};
use crate::core::{
    error::{BlockchainError, DiskContext},
    storage::SledStorage
};
use super::{NetworkProvider, AssetProvider};

#[async_trait]
pub trait BalanceProvider: AssetProvider + NetworkProvider {
    // Check if a balance exists for asset and key
    async fn has_balance_for(&self, key: &PublicKey, asset: &Hash) -> Result<bool, BlockchainError>;

    // Check if a balance exists for asset and key at specific topoheight
    async fn has_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError>;

    // Get the balance at a specific topoheight for asset and key
    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError>;

    // Get the balance under or equal topoheight requested for asset and key
    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError>;

    // Get the last topoheight that the account has a balance
    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<TopoHeight, BlockchainError>;

    // Get a new versioned balance of the account, this is based on the requested topoheight
    // And is returning the versioned balance at maximum topoheight
    // Versioned balance as the previous topoheight set also based on which height it is set
    // So, if we are at topoheight 50 and we have a balance at topoheight 40, the previous topoheight will be 40
    // But also if we have a balance at topoheight 50, the previous topoheight will also be 50
    // This must be called only to create a new versioned balance for the next topoheight as it's keeping changes from the balance at same topo
    async fn get_new_versioned_balance(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError>;

    // Search the highest balance where we have a outgoing TX
    async fn get_output_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError>;

    // Get the last balance of the account, this is based on the last topoheight (pointer) available
    async fn get_last_balance(&self, key: &PublicKey, asset: &Hash) -> Result<(TopoHeight, VersionedBalance), BlockchainError>;

    // Get the asset versioned balances for multiple keys
    async fn get_versioned_balances<'a, I: Iterator<Item = &'a PublicKey> + Send>(&self, asset: &Hash, keys: I, maximum_topoheight: TopoHeight) -> Result<Vec<Option<VersionedBalance>>, BlockchainError>;

    // Set the last topoheight for this asset and key to the requested topoheight
    fn set_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError>;

    // Set the last balance of the account, update the last topoheight pointer for asset and key
    // This is same as `set_last_topoheight_for_balance` but will also update the versioned balance
    async fn set_last_balance_to(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight, version: &VersionedBalance) -> Result<(), BlockchainError>;

    // Set the balance at specific topoheight for asset and key
    async fn set_balance_at_topoheight(&mut self, asset: &Hash, topoheight: TopoHeight, key: &PublicKey, balance: &VersionedBalance) -> Result<(), BlockchainError>;

    // Delete the balance at specific topoheight for asset and key
    async fn delete_balance_at_topoheight(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError>;

    // Delete the last topoheight for asset and key
    // This will only remove the pointer, not the version itself
    fn delete_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash) -> Result<(), BlockchainError>;

    // Get the account summary for a key and asset on the specified topoheight range
    // If None is returned, that means there was no changes that occured in the specified topoheight range
    async fn get_account_summary_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<Option<AccountSummary>, BlockchainError>;

    // Get the spendable balances for a key and asset on the specified topoheight (exclusive) range
    // Maximum 1024 entries per Vec<Balance>, Option<TopoHeight> is Some if we have others previous versions available and Vec is full.
    // It will stop at the first output balance found without including it
    async fn get_spendable_balances_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<(Vec<Balance>, Option<TopoHeight>), BlockchainError>;
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
    pub fn get_versioned_balance_key(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> [u8; 72] {
        trace!("get versioned balance {} key at {} for {}", asset, topoheight, key.as_address(self.is_mainnet()));
        let mut bytes = [0; 72];
        bytes[0..8].copy_from_slice(&topoheight.to_be_bytes());
        bytes[8..40].copy_from_slice(key.as_bytes());
        bytes[40..72].copy_from_slice(asset.as_bytes());

        bytes
    }

    async fn has_balance_internal(&self, key: &[u8; 64]) -> Result<bool, BlockchainError> {
        trace!("has balance internal");
        self.contains_data(&self.balances, key)
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
    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<TopoHeight, BlockchainError> {
        trace!("get last topoheight for balance {} for {}", asset, key.as_address(self.is_mainnet()));
        let key = self.get_balance_key_for(key, asset);
        if !self.has_balance_internal(&key).await? {
            return Ok(0)
        }

        self.get_cacheable_data(&self.balances, &None, &key, DiskContext::LastTopoHeightForBalance).await
    }

    // set in storage the new top topoheight (the most up-to-date versioned balance)
    fn set_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set last topoheight to {} for balance {} for {}", topoheight, asset, key.as_address(self.is_mainnet()));
        let key = self.get_balance_key_for(key, asset);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.balances, &key, &topoheight.to_be_bytes())?;
        Ok(())
    }

    // get the balance at a specific topoheight
    // if there is no balance change at this topoheight just return an error
    async fn has_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has balance {} for {} at exact topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        // check first that this address has balance, if no returns
        if !self.has_balance_for(key, asset).await? {
            return Ok(false)
        }

        let key = self.get_versioned_balance_key(key, asset, topoheight);
        self.contains_data(&self.versioned_balances, &key)
    }

    // get the balance at a specific topoheight
    // if there is no balance change at this topoheight just return an error
    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError> {
        trace!("get balance {} for {} at exact topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        // check first that this address has balance, if no returns
        if !self.has_balance_at_exact_topoheight(key, asset, topoheight).await? {
            trace!("No balance {} found for {} at exact topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
            return Err(BlockchainError::NoBalanceChanges(key.as_address(self.is_mainnet()), topoheight, asset.clone()))
        }

        let disk_key = self.get_versioned_balance_key(key, asset, topoheight);
        self.get_cacheable_data(&self.versioned_balances, &None, &disk_key, DiskContext::BalanceAtTopoHeight).await
            .map_err(|_| BlockchainError::NoBalanceChanges(key.as_address(self.is_mainnet()), topoheight, asset.clone()))
    }

    // delete the last topoheight registered for this key
    // it can happens when rewinding chain and we don't have any changes (no transaction in/out) for this key
    // because all versioned balances got deleted
    fn delete_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash) -> Result<(), BlockchainError> {
        trace!("delete last topoheight balance {} for {}", asset, key.as_address(self.is_mainnet()));
        let key = self.get_balance_key_for(key, asset);
        Self::remove_from_disk_without_reading(self.snapshot.as_mut(), &self.balances, &key)?;
        Ok(())
    }

    // get the latest balance at maximum specified topoheight
    // when a DAG re-ordering happens, we need to select the right balance and not the last one
    // returns None if the key has no balances for this asset
    // Maximum topoheight is inclusive
    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        trace!("get balance {} for {} at maximum topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        // check first that this address has balance for this asset, if no returns None
        if !self.has_balance_for(key, asset).await? {
            trace!("No balance {} found for {} at maximum topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
            return Ok(None)
        }

        let topo = self.get_last_topoheight_for_balance(key, asset).await?;
        let mut previous_topoheight = Some(topo);
        // otherwise, we have to go through the whole chain
        while let Some(topo) = previous_topoheight {
            if topo <= topoheight {
                let version = self.get_balance_at_exact_topoheight(key, asset, topo).await?;
                return Ok(Some((topo, version)))
            }

            previous_topoheight = self.load_from_disk(&self.versioned_balances, &self.get_versioned_balance_key(key, asset, topo), DiskContext::BalanceAtTopoHeight)?;
        }

        Ok(None)
    }

    // delete versioned balances for this topoheight
    async fn delete_balance_at_topoheight(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError> {
        trace!("delete balance {} for {} at topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        let disk_key = self.get_versioned_balance_key(key, asset, topoheight);
        Self::delete_cacheable_data(self.snapshot.as_mut(), &self.versioned_balances, &None, &disk_key).await
            .map_err(|_| BlockchainError::NoBalanceChanges(key.as_address(self.is_mainnet()), topoheight, asset.clone()))
    }

    // returns a new versioned balance with already-set previous topoheight
    // Topoheight is the new topoheight for the versioned balance,
    // We create a new versioned balance by taking the previous version and setting it as previous topoheight
    async fn get_new_versioned_balance(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError> {
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

    async fn get_output_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        trace!("get output balance {} for {} at maximum topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        if !self.has_balance_for(key, asset).await? {
            trace!("No balance {} found for {} at maximum topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
            return Ok(None)
        }

        let topo = self.get_last_topoheight_for_balance(key, asset).await?;
        let mut next = Some(topo);
        while let Some(topo) = next {
            // We read the next topoheight (previous topo of the versioned balance) and its current balance type
            let (prev_topo, balance_type): (Option<u64>, BalanceType) = self.load_from_disk(&self.versioned_balances, &self.get_versioned_balance_key(key, asset, topo), DiskContext::BalanceAtTopoHeight)?;
            if topo <= topoheight && balance_type.contains_output() {
                let version = self.get_balance_at_exact_topoheight(key, asset, topo).await?;
                return Ok(Some((topo, version)))
            }

            next = prev_topo;
        }

        Ok(None)
    }

    // save a new versioned balance in storage and update the pointer
    async fn set_last_balance_to(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight, version: &VersionedBalance) -> Result<(), BlockchainError> {
        trace!("set balance {} for {} to topoheight {}", asset, key.as_address(self.is_mainnet()), topoheight);
        self.set_balance_at_topoheight(asset, topoheight, key, &version).await?;
        self.set_last_topoheight_for_balance(key, asset, topoheight)?;
        Ok(())
    }

    // get the last version of balance and returns topoheight
    async fn get_last_balance(&self, key: &PublicKey, asset: &Hash) -> Result<(TopoHeight, VersionedBalance), BlockchainError> {
        trace!("get last balance {} for {}", asset, key.as_address(self.is_mainnet()));
        if !self.has_balance_for(key, asset).await? {
            trace!("No balance {} found for {}", asset, key.as_address(self.is_mainnet()));
            return Err(BlockchainError::NoBalance(key.as_address(self.is_mainnet())))
        }

        let topoheight = self.get_cacheable_data(&self.balances, &None, &self.get_balance_key_for(key, asset), DiskContext::LastBalance).await?;
        let version = self.get_balance_at_exact_topoheight(key, asset, topoheight).await?;
        Ok((topoheight, version))
    }

    async fn get_versioned_balances<'a, I: Iterator<Item = &'a PublicKey> + Send>(&self, asset: &Hash, keys: I, maximum_topoheight: TopoHeight) -> Result<Vec<Option<VersionedBalance>>, BlockchainError> {
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
    async fn set_balance_at_topoheight(&mut self, asset: &Hash, topoheight: TopoHeight, key: &PublicKey, balance: &VersionedBalance) -> Result<(), BlockchainError> {
        trace!("set balance {} at topoheight {} for {}", asset, topoheight, key.as_address(self.is_mainnet()));
        let key = self.get_versioned_balance_key(key, asset, topoheight);
        Self::insert_into_disk(self.snapshot.as_mut(), &self.versioned_balances, &key, balance.to_bytes())?;

        Ok(())
    }

    async fn get_account_summary_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<Option<AccountSummary>, BlockchainError> {
        trace!("get account summary {} for {} at maximum topoheight {}", asset, key.as_address(self.is_mainnet()), max_topoheight);

        // first search if we have a valid balance at the maximum topoheight
        if let Some((topo, version)) = self.get_balance_at_maximum_topoheight(key, asset, max_topoheight).await? {
            if topo < min_topoheight {
                trace!("No changes found for {} above min topoheight {}", key.as_address(self.is_mainnet()), min_topoheight);
                return Ok(None)
            }

            
            let mut account = AccountSummary {
                output_topoheight: None,
                stable_topoheight: topo,
            };
            
            // We have an output in it, we can return the account
            if version.contains_output() {
                trace!("Stable with output balance found for {} at topoheight {}", key.as_address(self.is_mainnet()), topo);
                return Ok(Some(account))
            }

            // We need to search through the whole history to see if we have a balance with output
            let mut previous = version.get_previous_topoheight();
            while let Some(topo) = previous {
                let previous_version = self.get_balance_at_exact_topoheight(key, asset, topo).await?;
                if previous_version.contains_output() {
                    trace!("Output balance found for {} at topoheight {}", key.as_address(self.is_mainnet()), topo);
                    account.output_topoheight = Some(topo);
                    break;
                }

                previous = previous_version.get_previous_topoheight();
            }

            return Ok(Some(account))
        }

        trace!("No balance found for {} at maximum topoheight {}", key.as_address(self.is_mainnet()), max_topoheight);
        Ok(None)
    }

    async fn get_spendable_balances_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<(Vec<Balance>, Option<TopoHeight>), BlockchainError> {
        trace!("get spendable balances for {} at maximum topoheight {}", key.as_address(self.is_mainnet()), max_topoheight);

        let mut balances = Vec::new();

        let mut fetch_topoheight = Some(max_topoheight);
        while let Some(topo) = fetch_topoheight.take().filter(|&t| t > min_topoheight && balances.len() < DEFAULT_MAX_ITEMS) {
            let version = self.get_balance_at_exact_topoheight(key, asset, topo).await?;
            let has_output = version.contains_output();
            let previous_topoheight = version.get_previous_topoheight();
            balances.push(version.as_balance(topo));

            if has_output {
                trace!("Output balance found for {} at topoheight {}", key.as_address(self.is_mainnet()), topo);
                break;
            } else {
                fetch_topoheight = previous_topoheight;
            }
        }

        trace!("balances {} {}, {} - {}", balances.len(), key.as_address(self.is_mainnet()), min_topoheight, max_topoheight);
        Ok((balances, fetch_topoheight))
    }
}