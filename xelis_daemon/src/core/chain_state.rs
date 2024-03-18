use std::collections::{hash_map::Entry, HashMap};
use log::{debug, trace};
use xelis_common::{
    account::{CiphertextCache, VersionedBalance, VersionedNonce},
    config::XELIS_ASSET,
    crypto::{elgamal::Ciphertext, Hash, PublicKey}
};
use super::{error::BlockchainError, storage::Storage};

// Sender changes
// This contains its expected next balance for next outgoing transactions
// But also contains the ciphertext changes happening (so a sum of each spendings for transactions)
// This is necessary to easily build the final user balance
struct Echange {
    // Version balance of the account
    version: VersionedBalance,
    // Sum of all transactions output
    output_sum: Ciphertext
}

impl Echange {
    async fn new(version: VersionedBalance) -> Result<Self, BlockchainError> {
        Ok(Self {
            version,
            output_sum: Ciphertext::zero(),
        })
    }

    // Get the right balance to use for TX verification
    fn get_mut_balance(&mut self) -> &mut CiphertextCache {
        // match self.version.get_mut_output_balance() {
        //     Some(balance) if self.use_output => return balance,
        //     _ => {}
        // }
        self.version.get_mut_balance()
    }

    // Add a change to the account
    fn add_output_to_sum(&mut self, output: Ciphertext) {
        self.output_sum += output;
    }
}

struct Account<'a> {
    // Account nonce used to verify valid transaction
    nonce: VersionedNonce,
    // Assets ready as source for any transfer/transaction
    // TODO: they must store also the ciphertext change
    // It will be added by next change at each TX
    // This is necessary to easily build the final user balance
    assets: HashMap<&'a Hash, Echange>
}

// This struct is used to verify the transactions executed at a snapshot of the blockchain
// It is read-only but write in memory the changes to the balances and nonces
// Once the verification is done, the changes are written to the storage
pub struct ChainState<'a, S: Storage> {
    // Storage to read and write the balances and nonces
    storage: &'a mut S,
    // Balances of the receiver accounts
    receiver_balances: HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>,
    // Sender accounts
    // This is used to verify ZK Proofs and store/update nonces
    accounts: HashMap<&'a PublicKey, Account<'a>>,
    // Current topoheight of the snapshot
    topoheight: u64,
    // Stable topoheight of the snapshot
    // This is used to determine if the balance is stable or not
    stable_topoheight: u64,
}

// TODO fix front running problem
impl<'a, S: Storage> ChainState<'a, S> {
    pub fn new(storage: &'a mut S, topoheight: u64, stable_topoheight: u64) -> Self {
        Self {
            storage,
            receiver_balances: HashMap::new(),
            accounts: HashMap::new(),
            topoheight,
            stable_topoheight,
        }
    }

    // Create a sender echange
    async fn create_sender_echange(storage: &S, key: &'a PublicKey, asset: &'a Hash, topoheight: u64) -> Result<Echange, BlockchainError> {
        let version = storage.get_new_versioned_balance(key, asset, topoheight).await?;
        Echange::new(version).await
    }

    // Create a sender account by fetching its nonce and create a empty HashMap for balances,
    // those will be fetched lazily
    async fn create_sender_account(key: &PublicKey, storage: &S, topoheight: u64) -> Result<Account<'a>, BlockchainError> {
        let (_, version) = storage
            .get_nonce_at_maximum_topoheight(key, topoheight).await?
            .ok_or_else(|| BlockchainError::AccountNotFound(key.as_address(storage.is_mainnet())))?;

        Ok(Account {
            nonce: version,
            assets: HashMap::new()
        })
    }

    // Retrieve the receiver balance of an account
    // This is mostly the final balance where everything is added (outputs and inputs)
    async fn get_receiver_balance<'b>(&'b mut self, key: &'a PublicKey, asset: &'a Hash) -> Result<&'b mut CiphertextCache, BlockchainError> {
        match self.receiver_balances.entry(key).or_insert_with(HashMap::new).entry(asset) {
            Entry::Occupied(o) => Ok(o.into_mut().get_mut_balance()),
            Entry::Vacant(e) => {
                let version = self.storage.get_new_versioned_balance(key, asset, self.topoheight).await?;
                Ok(e.insert(version).get_mut_balance())
            }
        }
    }

    // Retrieve the sender balance of an account
    // This is used for TX outputs verification
    // This depends on the transaction and can be final balance or output balance
    async fn get_sender_balance<'b>(&'b mut self, key: &'a PublicKey, asset: &'a Hash) -> Result<&'b mut CiphertextCache, BlockchainError> {
        match self.accounts.entry(key) {
            Entry::Occupied(o) => {
                let account = o.into_mut();
                match account.assets.entry(asset) {
                    Entry::Occupied(o) => Ok(o.into_mut().get_mut_balance()),
                    Entry::Vacant(e) => {
                        let echange = Self::create_sender_echange(&self.storage, key, asset, self.topoheight).await?;
                        Ok(e.insert(echange).get_mut_balance())
                    }
                }
            },
            Entry::Vacant(e) => {
                // Create a new account for the sender
                let account = Self::create_sender_account(key, &self.storage, self.topoheight).await?;

                // Create a new echange for the asset
                let echange = Self::create_sender_echange(&self.storage, key, asset, self.topoheight).await?;

                Ok(e.insert(account).assets.entry(asset).or_insert(echange).get_mut_balance())
            }
        }
    }

    // Update the output echanges of an account
    // Account must have been fetched before calling this function
    async fn internal_update_sender_echange(&mut self, key: &'a PublicKey, asset: &'a Hash, new_ct: Ciphertext) -> Result<(), BlockchainError> {
        let change = self.accounts.get_mut(key)
            .and_then(|a| a.assets.get_mut(asset))
            .ok_or_else(|| BlockchainError::NoTxSender(key.as_address(self.storage.is_mainnet())))?;

        // Increase the total output
        change.add_output_to_sum(new_ct);

        Ok(())
    }

    // Retrieve the account nonce
    // Only sender accounts should be used here
    async fn internal_get_account_nonce(&mut self, key: &'a PublicKey) -> Result<u64, BlockchainError> {
        match self.accounts.entry(key) {
            Entry::Occupied(o) => Ok(o.get().nonce.get_nonce()),
            Entry::Vacant(e) => {
                let account = Self::create_sender_account(key, &self.storage, self.topoheight).await?;
                Ok(e.insert(account).nonce.get_nonce())
            }
        }
    }

    // Update the account nonce
    // Only sender accounts should be used here
    // For each TX, we must update the nonce by one
    async fn internal_update_account_nonce(&mut self, account: &'a PublicKey, new_nonce: u64) -> Result<(), BlockchainError> {
        match self.accounts.entry(account) {
            Entry::Occupied(mut o) => {
                let account = o.get_mut();
                account.nonce.set_nonce(new_nonce);
            },
            Entry::Vacant(e) => {
                let mut account = Self::create_sender_account(account, &self.storage, self.topoheight).await?;
                // Update nonce
                account.nonce.set_nonce(new_nonce);

                // Store it
                e.insert(account);
            }
        }
        Ok(())
    }

    // Reward a miner for the block mined
    pub async fn reward_miner(&mut self, miner: &'a PublicKey, reward: u64) -> Result<(), BlockchainError> {
        debug!("Rewarding miner {} with {} XEL at topoheight {}", miner.as_address(self.storage.is_mainnet()), reward, self.topoheight);
        let miner_balance = self.get_receiver_balance(miner, &XELIS_ASSET).await?;
        *miner_balance.computable()? += reward;

        Ok(())
    }

    // This function is called after the verification of all needed transactions
    // This will consume ChainState and apply all changes to the storage
    // In case of incoming and outgoing transactions in same state, the final balance will be computed
    pub async fn apply_changes(mut self) -> Result<(), BlockchainError> {
        // Store every new nonce
        for (key, account) in &mut self.accounts {
            trace!("Saving versioned nonce {} for {} at topoheight {}", account.nonce, key.as_address(self.storage.is_mainnet()), self.topoheight);
            self.storage.set_last_nonce_to(key, self.topoheight, &account.nonce).await?;

            let balances = self.receiver_balances.entry(&key).or_insert_with(HashMap::new);
            // Because account balances are only used to verify the validity of ZK Proofs, we can't store them
            // We have to recompute the final balance for each asset using the existing current balance
            // Otherwise, we could have a front running problem
            // Example: Alice sends 100 to Bob, Bob sends 100 to Charlie
            // But Bob built its ZK Proof with the balance before Alice's transaction
            for (asset, echange) in account.assets.drain() {
                let Echange { version, output_sum, .. } = echange;
                match balances.entry(asset) {
                    Entry::Occupied(mut o) => {
                        // We got incoming funds while spending some
                        // We need to split the version in two
                        // Output balance is the balance after outputs spent without incoming funds
                        // Final balance is the balance after incoming funds + outputs spent
                        // This is a necessary process for the following case:
                        // Alice sends 100 to Bob in block 1000
                        // But Bob build 2 txs before Alice, one to Charlie and one to David
                        // First Tx of Blob is in block 1000, it will be valid
                        // But because of Alice incoming, the second Tx of Bob will be invalid
                        let final_version = o.get_mut();
                        final_version.set_output_balance(version.take_balance());

                        // Build the final balance
                        // This include all output and all inputs
                        let final_balance = final_version.get_mut_balance().computable()?;
                        *final_balance += output_sum;
                    },
                    Entry::Vacant(e) => {
                        // We have no incoming update for this key
                        // We can set the new sender balance as it is
                        e.insert(version);
                    }
                }
            }
        }

        // Apply all balances changes at topoheight
        for (account, balances) in self.receiver_balances {
            for (asset, version) in balances {
                trace!("Saving versioned balance {} for {} at topoheight {}", version, account.as_address(self.storage.is_mainnet()), self.topoheight);
                self.storage.set_last_balance_to(account, asset, self.topoheight, &version).await?;
            }

            // If the account has no nonce set, set it to 0
            if !self.accounts.contains_key(account) && !self.storage.has_nonce(account).await? {
                debug!("{} has now a balance but without any nonce registered, set default (0) nonce", account.as_address(self.storage.is_mainnet()));
                self.storage.set_last_nonce_to(account, self.topoheight, &VersionedNonce::new(0, None)).await?;
            }
        }

        Ok(())
    }
}