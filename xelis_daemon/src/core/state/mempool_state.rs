use std::collections::{hash_map::Entry, HashMap};
use async_trait::async_trait;
use xelis_common::{
    account::Nonce,
    block::{BlockVersion, TopoHeight},
    crypto::{
        elgamal::Ciphertext,
        Hash,
        PublicKey
    },
    transaction::{
        verify::BlockchainVerificationState,
        MultiSigPayload,
        Reference,
        Transaction
    }
};
use crate::core::{
    error::BlockchainError,
    mempool::Mempool,
    storage::Storage
};

struct Account<'a> {
    // Account nonce used to verify valid transaction
    nonce: u64,
    // Assets ready as source for any transfer/transaction
    // TODO: they must store also the ciphertext change
    // It will be added by next change at each TX
    // This is necessary to easily build the final user balance
    assets: HashMap<&'a Hash, Ciphertext>,
    // Multisig configured
    // This is used to verify the validity of the multisig setup
    multisig: Option<MultiSigPayload>
}

pub struct MempoolState<'a, S: Storage> {
    // If the provider is mainnet or not
    mainnet: bool,
    // Mempool from which it's backed
    mempool: &'a Mempool,
    // Storage in case sender balances aren't in mempool cache
    storage: &'a S,
    // Receiver balances
    receiver_balances: HashMap<&'a PublicKey, HashMap<&'a Hash, Ciphertext>>,
    // Sender accounts
    // This is used to verify ZK Proofs and store/update nonces
    accounts: HashMap<&'a PublicKey, Account<'a>>,
    // The current stable topoheight of the chain
    stable_topoheight: TopoHeight,
    // The current topoheight of the chain
    topoheight: TopoHeight,
    // Block header version
    block_version: BlockVersion,
}

impl<'a, S: Storage> MempoolState<'a, S> {
    pub fn new(mempool: &'a Mempool, storage: &'a S, stable_topoheight: TopoHeight, topoheight: TopoHeight, block_version: BlockVersion, mainnet: bool) -> Self {
        Self {
            mainnet,
            mempool,
            storage,
            receiver_balances: HashMap::new(),
            accounts: HashMap::new(),
            stable_topoheight,
            topoheight,
            block_version,
        }
    }

    // Retrieve the sender cache (inclunding balances and multisig)
    pub fn get_sender_cache(&mut self, key: &PublicKey) -> Option<(HashMap<&Hash, Ciphertext>, Option<MultiSigPayload>)> {
        let account = self.accounts.remove(key)?;
        Some((account.assets, account.multisig))
    }

    // Retrieve the receiver balance
    // We never store the receiver balance in mempool, only outgoing balances
    // So we just get it from our internal cache or from storage
    async fn internal_get_receiver_balance<'b>(&'b mut self, account: &'a PublicKey, asset: &'a Hash) -> Result<&'b mut Ciphertext, BlockchainError> {
        match self.receiver_balances.entry(account).or_insert_with(HashMap::new).entry(asset) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let version = self.storage.get_new_versioned_balance(account, asset, self.topoheight).await?;
                Ok(entry.insert(version.take_balance().take_ciphertext()?))
            }
        }
    }

    // Retrieve the versioned balance based on the TX reference 
    async fn get_versioned_balance_for_reference(storage: &S, key: &PublicKey, asset: &Hash, current_topoheight: TopoHeight, reference: &Reference) -> Result<Ciphertext, BlockchainError> {
        let (output, _, version) = super::search_versioned_balance_for_reference(storage, key, asset, current_topoheight, reference).await?;

        Ok(version.take_balance_with(output).take_ciphertext()?)
    }

    // Retrieve the nonce & the multisig state for a sender account
    async fn create_sender_account(mempool: &Mempool, storage: &S, key: &'a PublicKey, topoheight: TopoHeight) -> Result<Account<'a>, BlockchainError> {
        let (nonce, multisig) = if let Some(cache) = mempool.get_cache_for(key) {
            let nonce = cache.get_next_nonce();
            let multisig = if let Some(multisig) = cache.get_multisig() {
                Some(multisig.clone())
            } else {
                storage.get_multisig_at_maximum_topoheight_for(key, topoheight).await?
                    .map(|(_, v)| v.take().map(|v| v.into_owned())).flatten()
            };

            (nonce, multisig)
        } else {
            let nonce = storage.get_nonce_at_maximum_topoheight(key, topoheight).await?
                .map(|(_, v)| v.get_nonce()).unwrap_or(0);

            let multisig = storage.get_multisig_at_maximum_topoheight_for(key, topoheight).await?
                .map(|(_, v)| v.take().map(|v| v.into_owned())).flatten();

            (nonce, multisig)
        };

        Ok(Account {
            nonce,
            assets: HashMap::new(),
            multisig
        })
    }

    // Retrieve the sender balance
    // For this, we first look in our internal cache,
    // If not found, we check in mempool cache,
    // If still not present, we check in storage and determine using reference
    // Which version to use
    async fn internal_get_sender_balance<'b>(&'b mut self, key: &'a PublicKey, asset: &'a Hash, reference: &Reference) -> Result<&'b mut Ciphertext, BlockchainError> {
        match self.accounts.entry(key) {
            Entry::Occupied(o) => {
                let account = o.into_mut();
                match account.assets.entry(asset) {
                    Entry::Occupied(entry) => Ok(entry.into_mut()),
                    Entry::Vacant(entry) => match self.mempool.get_cache_for(key) {
                        Some(cache) => {
                            if let Some(version) = cache.get_balances().get(asset) {
                                Ok(entry.insert(version.clone()))
                            } else {
                                let ct = Self::get_versioned_balance_for_reference(&self.storage, key, asset, self.topoheight, reference).await?;
                                Ok(entry.insert(ct))
                            }
                        },
                        None => {
                            let ct = Self::get_versioned_balance_for_reference(&self.storage, key, asset, self.topoheight, reference).await?;
                            Ok(entry.insert(ct))
                        }
                    }
                }
            },
            Entry::Vacant(e) => {
                let account = e.insert(Self::create_sender_account(&self.mempool, &self.storage, key, self.topoheight).await?);

                match account.assets.entry(asset) {
                    Entry::Occupied(entry) => Ok(entry.into_mut()),
                    Entry::Vacant(entry) => {
                        let version = self.storage.get_new_versioned_balance(key, asset, self.topoheight).await?;
                        Ok(entry.insert(version.take_balance().take_ciphertext()?))
                    }
                }
            }
        }
    }

    // Retrieve the account nonce
    // Only sender accounts should be used here
    async fn internal_get_account_nonce(&mut self, key: &'a PublicKey) -> Result<Nonce, BlockchainError> {
        match self.accounts.entry(key) {
            Entry::Occupied(o) => Ok(o.get().nonce),
            Entry::Vacant(e) => {
                let account = Self::create_sender_account(&self.mempool, &self.storage, key, self.topoheight).await?;
                Ok(e.insert(account).nonce)
            }
        }
    }

    // Update the account nonce
    // Only sender accounts should be used here
    // For each TX, we must update the nonce by one
    async fn internal_update_account_nonce(&mut self, account: &'a PublicKey, new_nonce: u64) -> Result<(), BlockchainError> {
        let account = self.accounts.get_mut(account).ok_or_else(|| BlockchainError::AccountNotFound(account.as_address(self.storage.is_mainnet())))?;
        account.nonce = new_nonce;

        Ok(())
    }
}

#[async_trait]
impl<'a, S: Storage> BlockchainVerificationState<'a, BlockchainError> for MempoolState<'a, S> {
    /// Verify the TX version and reference
    async fn pre_verify_tx<'b>(
        &'b mut self,
        tx: &Transaction,
    ) -> Result<(), BlockchainError> {
        super::pre_verify_tx(self.storage, tx, self.stable_topoheight, self.topoheight, self.get_block_version()).await
    }

    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance<'b>(
        &'b mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
    ) -> Result<&'b mut Ciphertext, BlockchainError> {
        self.internal_get_receiver_balance(account, asset).await
    }

    /// Get the balance ciphertext used for verification of funds for the sender account
    async fn get_sender_balance<'b>(
        &'b mut self,
        account: &'a PublicKey,
        asset: &'a Hash,
        reference: &Reference,
    ) -> Result<&'b mut Ciphertext, BlockchainError> {
        self.internal_get_sender_balance(account, asset, reference).await
    }

    /// Apply new output to a sender account
    /// In this state, we don't need to store the output
    async fn add_sender_output(
        &mut self,
        _: &'a PublicKey,
        _: &'a Hash,
        _: Ciphertext,
    ) -> Result<(), BlockchainError> {
        Ok(())
    }

    /// Get the nonce of an account
    async fn get_account_nonce(
        &mut self,
        account: &'a PublicKey
    ) -> Result<Nonce, BlockchainError> {
        self.internal_get_account_nonce(account).await
    }

    /// Apply a new nonce to an account
    async fn update_account_nonce(
        &mut self,
        account: &'a PublicKey,
        new_nonce: Nonce
    ) -> Result<(), BlockchainError> {
        self.internal_update_account_nonce(account, new_nonce).await
    }

    /// Get the block version
    fn get_block_version(&self) -> BlockVersion {
        self.block_version
    }

    /// Set the multisig state for an account
    async fn set_multisig_state(
        &mut self,
        account: &'a PublicKey,
        payload: &MultiSigPayload
    ) -> Result<(), BlockchainError> {
        let account = self.accounts.get_mut(account).ok_or_else(|| BlockchainError::AccountNotFound(account.as_address(self.mainnet)))?;
        if payload.is_delete() {
            account.multisig = None;
        } else {
            account.multisig = Some(payload.clone());
        }

        Ok(())
    }

    /// Get the multisig state for an account
    /// If the account is not a multisig account, return None
    async fn get_multisig_state(
        &mut self,
        account: &'a PublicKey
    ) -> Result<Option<&MultiSigPayload>, BlockchainError> {
        self.accounts.get(account)
            .map(|a| a.multisig.as_ref())
            .ok_or_else(|| BlockchainError::AccountNotFound(account.as_address(self.storage.is_mainnet())))
    }
}