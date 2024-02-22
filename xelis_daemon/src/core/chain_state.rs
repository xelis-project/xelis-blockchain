use std::collections::{hash_map::Entry, HashMap};
use log::{debug, trace};
use xelis_common::{account::{BalanceRepresentation, VersionedBalance, VersionedNonce}, config::XELIS_ASSET, crypto::{Hash, PublicKey}};
use super::{error::BlockchainError, storage::Storage};


// This struct is used to verify the transactions executed at a snapshot of the blockchain
// It is read-only but write in memory the changes to the balances and nonces
// Once the verification is done, the changes are written to the storage
pub struct ChainState<'a, S: Storage> {
    // Storage to read and write the balances and nonces
    storage: &'a mut S,
    // Balances of the accounts
    balances: HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>,
    // Nonces of the accounts
    nonces: HashMap<&'a PublicKey, VersionedNonce>,
    // Current topoheight of the snapshot
    topoheight: u64,
    // All fees collected from the transactions
    fees_collected: u64,
}

impl<'a, S: Storage> ChainState<'a, S> {
    pub fn new(storage: &'a mut S, topoheight: u64) -> Self {
        Self {
            storage,
            balances: HashMap::new(),
            nonces: HashMap::new(),
            topoheight,
            fees_collected: 0,
        }
    }

    async fn internal_get_account_balance(&mut self, account: &'a PublicKey, asset: &'a Hash) -> Result<BalanceRepresentation, BlockchainError> {
        match self.balances.entry(account).or_insert_with(HashMap::new).entry(asset) {
            Entry::Occupied(o) => Ok(*o.get().get_balance()),
            Entry::Vacant(e) => {
                let (_, version) = self.storage
                    .get_balance_at_maximum_topoheight(account, asset, self.topoheight).await?
                    .ok_or_else(|| BlockchainError::AccountNotFound(account.clone()))?;

                Ok(*e.insert(version).get_balance())
            }
        }
    }

    async fn internal_update_account_balance(&mut self, account: &'a PublicKey, asset: &'a Hash, new_ct: BalanceRepresentation) -> Result<(), BlockchainError> {
        match self.balances.entry(account).or_insert_with(HashMap::new).entry(asset) {
            Entry::Occupied(mut o) => {
                let version = o.get_mut();
                version.set_balance(new_ct);
            },
            Entry::Vacant(e) => {
                let (_, version) = self.storage
                    .get_balance_at_maximum_topoheight(account, asset, self.topoheight).await?
                    .ok_or_else(|| BlockchainError::AccountNotFound(account.clone()))?;

                e.insert(version).set_balance(new_ct);
            }
        }
        Ok(())
    }

    async fn internal_get_account_nonce(&mut self, account: &'a PublicKey) -> Result<u64, BlockchainError> {
        match self.nonces.entry(account) {
            Entry::Occupied(o) => Ok(o.get().get_nonce()),
            Entry::Vacant(e) => {
                let (_, version) = self.storage
                    .get_nonce_at_maximum_topoheight(account, self.topoheight).await?
                    .ok_or_else(|| BlockchainError::AccountNotFound(account.clone()))?;

                Ok(e.insert(version).get_nonce())
            }
        }
    }

    async fn internal_update_account_nonce(&mut self, account: &'a PublicKey, new_nonce: u64) -> Result<(), BlockchainError> {
        match self.nonces.entry(account) {
            Entry::Occupied(mut o) => {
                let version = o.get_mut();
                version.set_nonce(new_nonce);
            },
            Entry::Vacant(e) => {
                let (_, version) = self.storage
                    .get_nonce_at_maximum_topoheight(account, self.topoheight).await?
                    .ok_or_else(|| BlockchainError::AccountNotFound(account.clone()))?;

                e.insert(version).set_nonce(new_nonce);
            }
        }
        Ok(())
    }

    // Reward a miner for the block mined
    pub async fn reward_miner(&mut self, miner: &'a PublicKey, asset: &'a Hash, _reward: u64) -> Result<(), BlockchainError> {
        let miner_balance = self.internal_get_account_balance(miner, asset).await?;
        // TODO add reward to miner balance
        self.internal_update_account_balance(miner, &XELIS_ASSET, miner_balance).await?;
        Ok(())
    }

    // This function is called after the verification of the transactions
    pub async fn apply_changes(self) -> Result<(), BlockchainError> {
        // Apply all balances changes at topoheight
        for (account, balances) in self.balances {
            for (asset, version) in balances {
                trace!("Saving versioned balance {} for {} at topoheight {}", version, account, self.topoheight);
                self.storage.set_last_balance_to(account, asset, self.topoheight, &version).await?;
            }

            // If the account has no nonce set, set it to 0
            if !self.nonces.contains_key(account) && !self.storage.has_nonce(account).await? {
                debug!("{} has now balance but without any nonce registered, set default (0) nonce", account);
                self.storage.set_last_nonce_to(account, self.topoheight, &VersionedNonce::new(0, None)).await?;
            }
        }

        // Store every new nonce
        for (account, version) in self.nonces {
            trace!("Saving versioned nonce {} for {} at topoheight {}", version, account, self.topoheight);
            self.storage.set_last_nonce_to(account, self.topoheight, &version).await?;
        }

        Ok(())
    }
}