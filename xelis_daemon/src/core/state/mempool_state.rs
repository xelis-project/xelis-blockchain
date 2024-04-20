use std::collections::{hash_map::Entry, HashMap};
use async_trait::async_trait;
use log::debug;
use xelis_common::{
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
    assets: HashMap<&'a Hash, Ciphertext>
}

pub struct MempoolState<'a, S: Storage> {
    // Mempool from which it's backed
    mempool: &'a Mempool,
    // Storage in case sender balances aren't in mempool cache
    storage: &'a S,
    // Receiver balances
    receiver_balances: HashMap<&'a PublicKey, HashMap<&'a Hash, Ciphertext>>,
    // Sender accounts
    // This is used to verify ZK Proofs and store/update nonces
    accounts: HashMap<&'a PublicKey, Account<'a>>,
    // The current topoheight of the chain
    topoheight: u64,
}

impl<'a, S: Storage> MempoolState<'a, S> {
    pub fn new(mempool: &'a Mempool, storage: &'a S, topoheight: u64) -> Self {
        Self {
            mempool,
            storage,
            receiver_balances: HashMap::new(),
            accounts: HashMap::new(),
            topoheight,
        }
    }

    // Retrieve the sender balances
    pub fn get_sender_balances(&mut self, key: &PublicKey) -> Option<HashMap<&Hash, Ciphertext>> {
        let account = self.accounts.remove(key)?;
        Some(account.assets)
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
    async fn get_versioned_balance_for_reference(storage: &S, key: &PublicKey, asset: &Hash, current_topoheight: u64, reference: &Reference) -> Result<Ciphertext, BlockchainError> {
        let (output, _, version) = super::search_versioned_balance_for_reference(storage, key, asset, current_topoheight, reference).await?;

        Ok(version.take_balance_with(output).take_ciphertext()?)
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
                let nonce = self.storage.get_nonce_at_maximum_topoheight(key, self.topoheight).await?
                    .map(|(_, v)| v.get_nonce()).unwrap_or(0);

                let account = e.insert(Account {
                    nonce,
                    assets: HashMap::new()
                });

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
    async fn internal_get_account_nonce(&mut self, key: &'a PublicKey) -> Result<u64, BlockchainError> {
        match self.accounts.entry(key) {
            Entry::Occupied(o) => Ok(o.get().nonce),
            Entry::Vacant(e) => match self.mempool.get_cache_for(key) {
                Some(cache) => Ok(cache.get_next_nonce()),
                None => {
                    let nonce = self.storage.get_nonce_at_maximum_topoheight(key, self.topoheight).await?
                        .map(|(_, v)| v.get_nonce()).unwrap_or(0);
    
                    let account = Account {
                        nonce,
                        assets: HashMap::new()
                    };
    
                    Ok(e.insert(account).nonce)
                }
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
                account.nonce = new_nonce;
            },
            Entry::Vacant(e) => {
                let account = Account {
                    nonce: new_nonce,
                    assets: HashMap::new()
                };

                // Store it
                e.insert(account);
            }
        }
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
        // Check the version
        if tx.get_version() != 0 {
            debug!("Invalid version: {}", tx.get_version());
            return Err(BlockchainError::InvalidTxVersion);
        }

        let required_fees = blockchain::estimate_required_tx_fees(self.storage, self.topoheight, tx).await?;
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