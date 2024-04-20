use std::{collections::{hash_map::Entry, HashMap}, ops::{Deref, DerefMut}};
use async_trait::async_trait;
use log::{debug, trace};
use xelis_common::{
    account::{
        BalanceType,
        CiphertextCache,
        VersionedBalance,
        VersionedNonce
    },
    config::XELIS_ASSET,
    crypto::{
        elgamal::Ciphertext,
        Hash,
        PublicKey
    },
    transaction::{
        verify::BlockchainVerificationState,
        Reference,
        Transaction
    },
    utils::format_xelis
};
use crate::core::{
    blockchain,
    error::BlockchainError,
    storage::Storage
};

// Sender changes
// This contains its expected next balance for next outgoing transactions
// But also contains the ciphertext changes happening (so a sum of each spendings for transactions)
// This is necessary to easily build the final user balance
struct Echange {
    // If we are allowed to use the output balance for verification
    allow_output_balance: bool,
    // if the versioned balance below is new for the current topoheight
    new_version: bool,
    // Version balance of the account used for the verification
    version: VersionedBalance,
    // Sum of all transactions output
    output_sum: Ciphertext,
    // If we used the output balance or not
    output_balance_used: bool,
}

impl Echange {
    fn new(allow_output_balance: bool, new_version: bool, version: VersionedBalance) -> Self {
        Self {
            allow_output_balance,
            new_version,
            version,
            output_sum: Ciphertext::zero(),
            output_balance_used: false,
        }
    }

    // Get the right balance to use for TX verification
    // TODO we may need to check previous balances and up to the last output balance made
    // So if in block A we spent TX A, and block B we got some funds, then we spent TX B in block C
    // We are still able to use it even if it was built at same time as TX A
    fn get_balance(&mut self) -> &mut CiphertextCache {
        let output = self.output_balance_used || self.allow_output_balance;
        let (ct, used) = self.version.select_balance(output);
        if !self.output_balance_used {
            self.output_balance_used = used;
        }
        ct
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

pub enum StorageReference<'a, S: Storage> {
    Mutable(&'a mut S),
    Immutable(&'a S)
}

impl<'a, S: Storage> AsRef<S> for StorageReference<'a, S> {
    fn as_ref(&self) -> &S {
        match self {
            Self::Mutable(s) => *s,
            Self::Immutable(s) => s
        }
    }
}

impl <'a, S: Storage> AsMut<S> for StorageReference<'a, S> {
    fn as_mut(&mut self) -> &mut S {
        match self {
            Self::Mutable(s) => *s,
            Self::Immutable(_) => panic!("Cannot mutably borrow immutable storage")
        }
    }
}

impl<'a, S: Storage> Deref for StorageReference<'a, S> {
    type Target = S;

    fn deref(&self) -> &S {
        self.as_ref()
    }
}

impl <'a, S: Storage> DerefMut for StorageReference<'a, S> {
    fn deref_mut(&mut self) -> &mut S {
        match self {
            Self::Mutable(s) => *s,
            Self::Immutable(_) => panic!("Cannot mutably borrow immutable storage")
        }
    }
}

// This struct is used to verify the transactions executed at a snapshot of the blockchain
// It is read-only but write in memory the changes to the balances and nonces
// Once the verification is done, the changes are written to the storage
pub struct ChainState<'a, S: Storage> {
    // Storage to read and write the balances and nonces
    storage: StorageReference<'a, S>,
    // Balances of the receiver accounts
    receiver_balances: HashMap<&'a PublicKey, HashMap<&'a Hash, VersionedBalance>>,
    // Sender accounts
    // This is used to verify ZK Proofs and store/update nonces
    accounts: HashMap<&'a PublicKey, Account<'a>>,
    // Current topoheight of the snapshot
    topoheight: u64
}

// Chain State that can be applied to the mutable storage
pub struct ApplicableChainState<'a, S: Storage> {
    inner: ChainState<'a, S>
}

impl<'a, S: Storage> Deref for ApplicableChainState<'a, S> {
    type Target = ChainState<'a, S>;

    fn deref(&self) -> &ChainState<'a, S> {
        &self.inner
    }
}

impl<'a, S: Storage> DerefMut for ApplicableChainState<'a, S> {
    fn deref_mut(&mut self) -> &mut ChainState<'a, S> {
        &mut self.inner
    }
}

impl<'a, S: Storage> AsRef<ChainState<'a, S>> for ApplicableChainState<'a, S> {
    fn as_ref(&self) -> &ChainState<'a, S> {
        &self.inner
    }
}

impl<'a, S: Storage> AsMut<ChainState<'a, S>> for ApplicableChainState<'a, S> {
    fn as_mut(&mut self) -> &mut ChainState<'a, S> {
        &mut self.inner
    }
}

impl<'a, S: Storage> ApplicableChainState<'a, S> {
    pub fn new(storage: &'a mut S, topoheight: u64) -> Self {
        Self {
            inner: ChainState::with(StorageReference::Mutable(storage), topoheight)
        }
    }

    // Get the storage used by the chain state
    pub fn get_mut_storage(&mut self) -> &mut S {
        self.inner.storage.as_mut()
    }

    // This function is called after the verification of all needed transactions
    // This will consume ChainState and apply all changes to the storage
    // In case of incoming and outgoing transactions in same state, the final balance will be computed
    pub async fn apply_changes(mut self) -> Result<(), BlockchainError> {
        // Apply changes for sender accounts
        for (key, account) in &mut self.inner.accounts {
            trace!("Saving {} for {} at topoheight {}", account.nonce, key.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
            self.inner.storage.set_last_nonce_to(key, self.inner.topoheight, &account.nonce).await?;

            let balances = self.inner.receiver_balances.entry(&key).or_insert_with(HashMap::new);
            // Because account balances are only used to verify the validity of ZK Proofs, we can't store them
            // We have to recompute the final balance for each asset using the existing current balance
            // Otherwise, we could have a front running problem
            // Example: Alice sends 100 to Bob, Bob sends 100 to Charlie
            // But Bob built its ZK Proof with the balance before Alice's transaction
            for (asset, echange) in account.assets.drain() {
                trace!("{} {} updated for {} at topoheight {}", echange.version, asset, key.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
                let Echange { version, output_sum, output_balance_used, new_version, .. } = echange;
                trace!("sender output sum: {:?}", output_sum.compress());
                match balances.entry(asset) {
                    Entry::Occupied(mut o) => {
                        trace!("{} already has a balance for {} at topoheight {}", key.as_address(self.inner.storage.is_mainnet()), asset, self.inner.topoheight);
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

                        // We got input and output funds, mark it
                        final_version.set_balance_type(BalanceType::Both);

                        // We must build output balance correctly
                        // For that, we use the same balance before any inputs
                        // And deduct outputs
                        // let clean_version = self.storage.get_new_versioned_balance(key, asset, self.topoheight).await?;
                        // let mut output_balance = clean_version.take_balance();
                        // *output_balance.computable()? -= &output_sum;

                        // Determine which balance to use as next output balance
                        // This is used in case TXs that are built at same reference, but
                        // executed in differents topoheights have the output balance reported
                        // to the next topoheight each time to stay valid during ZK Proof verification
                        let output_balance = version.take_balance_with(output_balance_used);

                        // Set to our final version the new output balance
                        final_version.set_output_balance(Some(output_balance));

                        // Build the final balance
                        // All inputs are already added, we just need to substract the outputs
                        let final_balance = final_version.get_mut_balance().computable()?;
                        *final_balance -= output_sum;
                    },
                    Entry::Vacant(e) => {
                        trace!("{} has no balance for {} at topoheight {}", key.as_address(self.inner.storage.is_mainnet()), asset, self.inner.topoheight);
                        // We have no incoming update for this key
                        // Select the right final version
                        // For that, we must check if we used the output balance and/or if we are not on the last version 
                        let mut version = if output_balance_used || !new_version {
                            // We must fetch again the version to sum it with the output
                            // This is necessary to build the final balance
                            let mut version = self.inner.storage.get_new_versioned_balance(key, asset, self.inner.topoheight).await?;
                            // Substract the output sum
                            trace!("{} has no balance for {} at topoheight {}, substract output sum", key.as_address(self.inner.storage.is_mainnet()), asset, self.inner.topoheight);
                            *version.get_mut_balance().computable()? -= output_sum;
                            version
                        } else {
                            // Version was based on final balance, all good, nothing to do
                            version
                        };

                        // We have some output, mark it
                        version.set_balance_type(BalanceType::Output);

                        e.insert(version);
                    }
                }
            }
        }

        // Apply all balances changes at topoheight
        // We injected the sender balances in the receiver balances previously
        for (account, balances) in self.inner.receiver_balances {
            for (asset, version) in balances {
                trace!("Saving versioned balance {} for {} at topoheight {}", version, account.as_address(self.inner.storage.is_mainnet()), self.inner.topoheight);
                self.inner.storage.set_last_balance_to(account, asset, self.inner.topoheight, &version).await?;
            }

            // If the account has no nonce set, set it to 0
            if !self.inner.accounts.contains_key(account) && !self.inner.storage.has_nonce(account).await? {
                debug!("{} has now a balance but without any nonce registered, set default (0) nonce", account.as_address(self.inner.storage.is_mainnet()));
                self.inner.storage.set_last_nonce_to(account, self.inner.topoheight, &VersionedNonce::new(0, None)).await?;
            }

            // Mark it as registered at this topoheight
            if !self.inner.storage.is_account_registered_below_topoheight(account, self.inner.topoheight).await? {
                self.inner.storage.set_account_registration_topoheight(account, self.inner.topoheight).await?;
            }
        }

        Ok(())
    }
}

impl<'a, S: Storage> ChainState<'a, S> {
    fn with(storage: StorageReference<'a, S>, topoheight: u64) -> Self {
        Self {
            storage,
            receiver_balances: HashMap::new(),
            accounts: HashMap::new(),
            topoheight
        }
    }

    pub fn new(storage: &'a S, topoheight: u64) -> Self {
        Self::with(StorageReference::Immutable(storage), topoheight)
    }

    // Get the storage used by the chain state
    pub fn get_storage(&self) -> &S {
        self.storage.as_ref()
    }

    pub fn get_sender_balances<'b>(&'b self, key: &'b PublicKey) -> Option<HashMap<&'b Hash, &'b VersionedBalance>> {
        let account = self.accounts.get(key)?;
        Some(account.assets.iter().map(|(k, v)| (*k, &v.version)).collect())
    }

    // Create a sender echange
    async fn create_sender_echange(storage: &S, key: &'a PublicKey, asset: &'a Hash, current_topoheight: u64, reference: &Reference) -> Result<Echange, BlockchainError> {
        let (use_output_balance, new_version, version) = super::search_versioned_balance_for_reference(storage, key, asset, current_topoheight, reference).await?;
        Ok(Echange::new(use_output_balance, new_version,  version))
    }

    // Create a sender account by fetching its nonce and create a empty HashMap for balances,
    // those will be fetched lazily
    async fn create_sender_account(key: &PublicKey, storage: &S, topoheight: u64) -> Result<Account<'a>, BlockchainError> {
        let (topo, mut version) = storage
            .get_nonce_at_maximum_topoheight(key, topoheight).await?
            .ok_or_else(|| BlockchainError::AccountNotFound(key.as_address(storage.is_mainnet())))?;
        version.set_previous_topoheight(Some(topo));

        Ok(Account {
            nonce: version,
            assets: HashMap::new()
        })
    }

    // Retrieve the receiver balance of an account
    // This is mostly the final balance where everything is added (outputs and inputs)
    async fn internal_get_receiver_balance<'b>(&'b mut self, key: &'a PublicKey, asset: &'a Hash) -> Result<&'b mut Ciphertext, BlockchainError> {
        match self.receiver_balances.entry(key).or_insert_with(HashMap::new).entry(asset) {
            Entry::Occupied(o) => Ok(o.into_mut().get_mut_balance().computable()?),
            Entry::Vacant(e) => {
                let version = self.storage.get_new_versioned_balance(key, asset, self.topoheight).await?;
                Ok(e.insert(version).get_mut_balance().computable()?)
            }
        }
    }

    // Retrieve the sender balance of an account
    // This is used for TX outputs verification
    // This depends on the transaction and can be final balance or output balance
    async fn internal_get_sender_verification_balance<'b>(&'b mut self, key: &'a PublicKey, asset: &'a Hash, reference: &Reference) -> Result<&'b mut CiphertextCache, BlockchainError> {
        trace!("getting sender verification balance for {} at topoheight {}, reference: {}", key.as_address(self.storage.is_mainnet()), self.topoheight, reference.topoheight);
        match self.accounts.entry(key) {
            Entry::Occupied(o) => {
                let account = o.into_mut();
                match account.assets.entry(asset) {
                    Entry::Occupied(o) => Ok(o.into_mut().get_balance()),
                    Entry::Vacant(e) => {
                        let echange = Self::create_sender_echange(&self.storage, key, asset, self.topoheight, reference).await?;
                        Ok(e.insert(echange).get_balance())
                    }
                }
            },
            Entry::Vacant(e) => {
                // Create a new account for the sender
                let account = Self::create_sender_account(key, &self.storage, self.topoheight).await?;

                // Create a new echange for the asset
                let echange = Self::create_sender_echange(&self.storage, key, asset, self.topoheight, reference).await?;

                Ok(e.insert(account).assets.entry(asset).or_insert(echange).get_balance())
            }
        }
    }

    // Update the output echanges of an account
    // Account must have been fetched before calling this function
    async fn internal_update_sender_echange(&mut self, key: &'a PublicKey, asset: &'a Hash, new_ct: Ciphertext) -> Result<(), BlockchainError> {
        trace!("update sender echange: {:?}", new_ct.compress());
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
        trace!("Updating nonce for {} to {} at topoheight {}", account.as_address(self.storage.is_mainnet()), new_nonce, self.topoheight);
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
        let miner_balance = self.internal_get_receiver_balance(miner, &XELIS_ASSET).await?;
        *miner_balance += reward;

        Ok(())
    }
}

#[async_trait]
impl<'a, S: Storage> BlockchainVerificationState<'a, BlockchainError> for ChainState<'a, S> {

    /// Verify the TX version and reference
    async fn pre_verify_tx<'b>(
        &'b mut self,
        tx: &Transaction,
    ) -> Result<(), BlockchainError> {
        // Check the version
        if tx.get_version() != 0 {
            debug!("Invalid version: {}", tx.get_version());
            return Err(BlockchainError::InvalidTxVersion);
        }

        // Verified that minimal fees are set
        let required_fees = blockchain::estimate_required_tx_fees(self.get_storage(), self.topoheight, tx).await?;
        if required_fees > tx.get_fee() {
            debug!("Invalid fees: {} required, {} provided", format_xelis(required_fees), format_xelis(tx.get_fee()));
            return Err(BlockchainError::InvalidTxFee(required_fees, tx.get_fee()));
        }

        let reference = tx.get_reference();
        // Verify that the block he is built upon exists
        if !self.storage.has_block_with_hash(&reference.hash).await? {
            debug!("Invalid reference: block {} not found", reference.hash);
            return Err(BlockchainError::InvalidReferenceHash);
        }

        // Verify that it is not a fake topoheight
        if self.topoheight < reference.topoheight {
            debug!("Invalid reference: topoheight {} is higher than chain {}", reference.topoheight, self.topoheight);
            return Err(BlockchainError::InvalidReferenceTopoheight);
        }

        Ok(())
    }

    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance<'b>(
        &'b mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
    ) -> Result<&'b mut Ciphertext, BlockchainError> {
        let ct = self.internal_get_receiver_balance(account, asset).await?;
        Ok(ct)
    }

    /// Get the balance ciphertext for a sender account
    async fn get_sender_balance<'b>(
        &'b mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
        reference: &Reference,
    ) -> Result<&'b mut Ciphertext, BlockchainError> {
        Ok(self.internal_get_sender_verification_balance(account, asset, reference).await?.computable()?)
    }

    /// Apply new output to a sender account
    async fn add_sender_output(
        &mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
        output: Ciphertext,
    ) -> Result<(), BlockchainError> {
        self.internal_update_sender_echange(account, asset, output).await
    }

    /// Get the nonce of an account
    async fn get_account_nonce(
        &mut self,
        account: &'a PublicKey
    ) -> Result<u64, BlockchainError> {
        self.internal_get_account_nonce(account).await
    }

    /// Apply a new nonce to an account
    async fn update_account_nonce(
        &mut self,
        account: &'a PublicKey,
        new_nonce: u64
    ) -> Result<(), BlockchainError> {
        self.internal_update_account_nonce(account, new_nonce).await
    }
} 