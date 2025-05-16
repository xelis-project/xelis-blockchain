use async_trait::async_trait;
use log::trace;
use xelis_common::{
    account::{
        AccountSummary, Balance, BalanceType, VersionedBalance
    },
    block::TopoHeight,
    crypto::{
        Hash,
        PublicKey
    },
};
use crate::core::{
    error::BlockchainError,
    storage::{
        rocksdb::{
            AccountId,
            AssetId,
            Column
        },
        BalanceProvider,
        NetworkProvider,
        RocksStorage
    }
};

#[async_trait]
impl BalanceProvider for RocksStorage {
    // Check if a balance exists for asset and key
    async fn has_balance_for(&self, key: &PublicKey, asset: &Hash) -> Result<bool, BlockchainError> {
        trace!("has balance for {} {}", key.as_address(self.is_mainnet()), asset);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;
        let key = Self::get_account_balance_key(account_id, asset_id);

        self.contains_data(Column::Balances, &key)
    }

    // Check if a balance exists for asset and key at specific topoheight
    async fn has_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<bool, BlockchainError> {
        trace!("has balance at exact topoheight {} for {} {}", topoheight, key.as_address(self.is_mainnet()), asset);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let key = Self::get_versioned_account_balance_key(account_id, asset_id, topoheight);
        self.contains_data(Column::VersionedBalances, &key)
    }

    // Get the balance at a specific topoheight for asset and key
    async fn get_balance_at_exact_topoheight(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<VersionedBalance, BlockchainError> {
        trace!("get balance at exact topoheight {} for {} {}", topoheight, key.as_address(self.is_mainnet()), asset);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let key = Self::get_versioned_account_balance_key(account_id, asset_id, topoheight);
        self.load_from_disk(Column::VersionedBalances, &key)
    }

    // Get the balance under or equal topoheight requested for asset and key
    async fn get_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        trace!("get balance at maximum topoheight {} for {} {}", maximum_topoheight, key.as_address(self.is_mainnet()), asset);
        let Some(account_id) = self.get_optional_account_id(key)? else {
            trace!("no account found for {}", key.as_address(self.is_mainnet()));
            return Ok(None);
        };
        let asset_id = self.get_asset_id(asset)?;

        let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, maximum_topoheight);
        // Check if we have a balance at exact topoheight
        let mut topo = if self.contains_data(Column::VersionedBalances, &versioned_key)? {
            trace!("using topoheight {}", maximum_topoheight);
            Some(maximum_topoheight)
        } else  {
            trace!("load latest version available");
            // skip the topoheight from the key, load the last topoheight
            self.load_optional_from_disk(Column::Balances, &versioned_key[8..24])?
        };

        // Iterate over our linked list of versions
        while let Some(topoheight) = topo {
            let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, topoheight);            
            if topoheight <= maximum_topoheight {
                trace!("versioned balance of {} asset {} found at {}", key.as_address(self.is_mainnet()), asset_id, topoheight);
                let version = self.load_from_disk(Column::VersionedBalances, &versioned_key)?;
                return Ok(Some((topoheight, version)));
            }

            topo = self.load_from_disk(Column::VersionedBalances, &versioned_key)?;
        }

        Ok(None)
    }

    // Get the last topoheight that the account has a balance
    async fn get_last_topoheight_for_balance(&self, key: &PublicKey, asset: &Hash) -> Result<TopoHeight, BlockchainError> {
        trace!("get last topoheight for balance {} {}", key.as_address(self.is_mainnet()), asset);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let key = Self::get_account_balance_key(account_id, asset_id);
        self.load_from_disk(Column::Balances, &key)
    }

    // Get a new versioned balance of the account, this is based on the requested topoheight
    // And is returning the versioned balance at maximum topoheight
    // Versioned balance as the previous topoheight set also based on which height it is set
    // So, if we are at topoheight 50 and we have a balance at topoheight 40, the previous topoheight will be 40
    // But also if we have a balance at topoheight 50, the previous topoheight will also be 50
    // This must be called only to create a new versioned balance for the next topoheight as it's keeping changes from the balance at same topo
    // Bool return type is true if the balance is new (no previous balance found)
    async fn get_new_versioned_balance(&self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<(VersionedBalance, bool), BlockchainError> {
        trace!("get new versioned balance for {} {} at topoheight {}", key.as_address(self.is_mainnet()), asset, topoheight);
        match self.get_balance_at_maximum_topoheight(key, asset, topoheight).await? {
            Some((topo, mut version)) => {
                trace!("Mark version as clean for {} {} at topoheight {}", key.as_address(self.is_mainnet()), asset, topo);
                // Mark it as clean
                version.prepare_new(Some(topo));
                Ok((version, false))
            },
            // if its the first balance, then we return a zero balance
            None => {
                trace!("no balance found, new version for {}", key.as_address(self.is_mainnet()));
                Ok((VersionedBalance::zero(), true))
            }
        }
    }

    // Search the highest balance where we have a outgoing TX
    async fn get_output_balance_at_maximum_topoheight(&self, key: &PublicKey, asset: &Hash, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        trace!("get output balance at maximum topoheight {} for {} {}", maximum_topoheight, key.as_address(self.is_mainnet()), asset);
        self.get_output_balance_in_range(key, asset, 0, maximum_topoheight).await
    }

    // Search the highest balance where we have a spending
    // To short-circuit the search, we stop if we go below the reference topoheight
    async fn get_output_balance_in_range(&self, key: &PublicKey, asset: &Hash, minimum_topoheight: TopoHeight, maximum_topoheight: TopoHeight) -> Result<Option<(TopoHeight, VersionedBalance)>, BlockchainError> {
        trace!("get output balance in range {} - {} for {} {}", minimum_topoheight, maximum_topoheight, key.as_address(self.is_mainnet()), asset);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, maximum_topoheight);
        let start_topo = if self.contains_data(Column::VersionedBalances, &versioned_key)? {
            trace!("balance found at topoheight {}, using it", maximum_topoheight);
            maximum_topoheight
        } else {
            trace!("balance not found at topoheight {}, loading last topoheight", maximum_topoheight);
            // skip the topoheight from the key, load the last topoheight
            self.load_from_disk(Column::Balances, &versioned_key[8..])?
        };

        let mut topo = Some(start_topo);
        // Iterate over our linked list of versions
        while let Some(topoheight) = topo {
            if topoheight < minimum_topoheight {
                // We reached the min, stop searching
                trace!("balance reached minimum topoheight {}, stopping search", minimum_topoheight);
                break;
            }

            let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, topoheight);
            let (prev_topo, balance_type): (Option<u64>, BalanceType) = self.load_from_disk(Column::VersionedBalances, &versioned_key)?;

            if topoheight <= maximum_topoheight && balance_type.contains_output() {
                trace!("balance of {} asset {} is updated at {}", key.as_address(self.is_mainnet()), asset_id, topoheight);
                let version = self.load_from_disk(Column::VersionedBalances, &versioned_key)?;
                return Ok(Some((topoheight, version)));
            }

            topo = prev_topo;
        }

        Ok(None)
    }

    // Get the last balance of the account, this is based on the last topoheight (pointer) available
    async fn get_last_balance(&self, key: &PublicKey, asset: &Hash) -> Result<(TopoHeight, VersionedBalance), BlockchainError> {
        trace!("get last balance for {} {}", key.as_address(self.is_mainnet()), asset);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let key = Self::get_account_balance_key(account_id, asset_id);
        let topoheight = self.load_from_disk(Column::Balances, &key)?;

        let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, topoheight);
        let versioned_balance = self.load_from_disk(Column::VersionedBalances, &versioned_key)?;

        Ok((topoheight, versioned_balance))
    }

    // Set the last topoheight for this asset and key to the requested topoheight
    fn set_last_topoheight_for_balance(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight) -> Result<(), BlockchainError> {
        trace!("set last topoheight for {} {} to {}", key.as_address(self.is_mainnet()), asset, topoheight);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let key = Self::get_account_balance_key(account_id, asset_id);
        self.insert_into_disk(Column::Balances, &key, &topoheight.to_be_bytes())
    }

    // Set the last balance of the account, update the last topoheight pointer for asset and key
    // This is same as `set_last_topoheight_for_balance` but will also update the versioned balance
    async fn set_last_balance_to(&mut self, key: &PublicKey, asset: &Hash, topoheight: TopoHeight, version: &VersionedBalance) -> Result<(), BlockchainError> {
        trace!("set last balance for {} {} to {}", key.as_address(self.is_mainnet()), asset, topoheight);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, topoheight);
        self.insert_into_disk(Column::Balances, &versioned_key[8..], &topoheight.to_be_bytes())?;
        self.insert_into_disk(Column::VersionedBalances, &versioned_key, version)
    }

    // Set the balance at specific topoheight for asset and key
    async fn set_balance_at_topoheight(&mut self, asset: &Hash, topoheight: TopoHeight, key: &PublicKey, balance: &VersionedBalance) -> Result<(), BlockchainError> {
        trace!("set balance at topoheight {} for {} {}", topoheight, key.as_address(self.is_mainnet()), asset);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, topoheight);
        self.insert_into_disk(Column::VersionedBalances, &versioned_key, balance)
    }

    // Get the account summary for a key and asset on the specified topoheight range
    // If None is returned, that means there was no changes that occured in the specified topoheight range
    async fn get_account_summary_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight) -> Result<Option<AccountSummary>, BlockchainError> {
        trace!("get account summary for {} {} min topoheight {} max topoheight {}", key.as_address(self.is_mainnet()), asset, min_topoheight, max_topoheight);
        // first search if we have a valid balance at the maximum topoheight
        if let Some((topo, version)) = self.get_balance_at_maximum_topoheight(key, asset, max_topoheight).await? {
            if topo < min_topoheight {
                trace!("balance found at topoheight {} below min topoheight {}, skipping", topo, min_topoheight);
                return Ok(None)
            }
            
            let mut account = AccountSummary {
                output_topoheight: None,
                stable_topoheight: topo,
            };

            // We have an output in it, we can return the account
            if version.contains_output() || version.get_previous_topoheight().is_none() {
                trace!("account summary found for {} {} at topoheight {}", key.as_address(self.is_mainnet()), asset, topo);
                return Ok(Some(account))
            }

            let account_id = self.get_account_id(key)?;
            let asset_id = self.get_asset_id(asset)?;

            // We need to search through the whole history to see if we have a balance with output
            let mut previous = version.get_previous_topoheight();
            while let Some(topo) = previous {
                let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, topo);
                let (previous_topo, balance_type): (Option<u64>, BalanceType) = self.load_from_disk(Column::VersionedBalances, &versioned_key)?;
                if balance_type.contains_output() {
                    trace!("balance containing output found for {} {} at topoheight {}", key.as_address(self.is_mainnet()), asset, topo);
                    account.output_topoheight = Some(topo);
                    break;
                }

                previous = previous_topo;
            }

            return Ok(Some(account))
        }

        Ok(None)
    }

    // Get the spendable balances for a key and asset on the specified topoheight (exclusive) range
    // Maximum 1024 entries per Vec<Balance>, Option<TopoHeight> is Some if we have others previous versions available and Vec is full.
    // It will stop at the first output balance found without including it
    async fn get_spendable_balances_for(&self, key: &PublicKey, asset: &Hash, min_topoheight: TopoHeight, max_topoheight: TopoHeight, maximum: usize) -> Result<(Vec<Balance>, Option<TopoHeight>), BlockchainError> {
        trace!("get spendable balances for {} {} min topoheight {} max topoheight {}", key.as_address(self.is_mainnet()), asset, min_topoheight, max_topoheight);
        let account_id = self.get_account_id(key)?;
        let asset_id = self.get_asset_id(asset)?;

        let mut balances = Vec::new();
        let mut next_topo = Some(max_topoheight);

        // NOTE: the take is important here as we return it below
        while let Some(topo) = next_topo.take().filter(|&t| t >= min_topoheight && balances.len() < maximum) {
            let versioned_key = Self::get_versioned_account_balance_key(account_id, asset_id, topo);
            let version = self.load_from_disk::<_, VersionedBalance>(Column::VersionedBalances, &versioned_key)?;
            let has_output = version.contains_output();
            let previous_topoheight = version.get_previous_topoheight();

            balances.push(version.as_balance(topo));

            // We have an output in it, we can return the account
            if has_output {
                trace!("output balance found for {} {} at topoheight {}", key.as_address(self.is_mainnet()), asset, topo);
                break;
            }

            next_topo = previous_topoheight;
        }

        Ok((balances, next_topo))
    }
}

impl RocksStorage {
    pub fn get_account_balance_key(account: AccountId, asset: AssetId) -> [u8; 16] {
        let mut buffer = [0; 16];
        buffer[0..8].copy_from_slice(&account.to_be_bytes());
        buffer[8..16].copy_from_slice(&asset.to_be_bytes());

        buffer
    }

    pub fn get_versioned_account_balance_key(account: AccountId, asset: AssetId, topoheight: TopoHeight) -> [u8; 24] {
        let mut buffer = [0; 24];
        buffer[0..8].copy_from_slice(&topoheight.to_be_bytes());
        buffer[8..16].copy_from_slice(&account.to_be_bytes());
        buffer[16..24].copy_from_slice(&asset.to_be_bytes());

        buffer
    }
}