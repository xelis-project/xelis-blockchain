mod apply;
mod storage;

use std::{
    borrow::Cow,
    collections::{hash_map::Entry, HashMap}
};
use async_trait::async_trait;
use log::{debug, trace};
use xelis_common::{
    account::{
        CiphertextCache,
        Nonce,
        VersionedBalance,
        VersionedNonce
    },
    block::{BlockVersion, TopoHeight},
    config::XELIS_ASSET,
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
    },
    utils::format_xelis
};
use xelis_environment::Environment;
use xelis_vm::Module;
use crate::core::{
    error::BlockchainError,
    storage::{
        Storage,
        VersionedState
    }
};

pub use apply::*;
pub use storage::*;

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
    assets: HashMap<&'a Hash, Echange>,
    // Multisig configured
    // This is used to verify the validity of the multisig setup
    multisig: Option<(VersionedState, Option<MultiSigPayload>)>
}

// This struct is used to verify the transactions executed at a snapshot of the blockchain
// It is read-only but write in memory the changes to the balances and nonces
// Once the verification is done, the changes are written to the storage
pub struct ChainState<'a, S: Storage> {
    // Storage to read and write the balances and nonces
    storage: StorageReference<'a, S>,
    environment: &'a Environment,
    // Balances of the receiver accounts
    receiver_balances: HashMap<Cow<'a, PublicKey>, HashMap<Cow<'a, Hash>, VersionedBalance>>,
    // Sender accounts
    // This is used to verify ZK Proofs and store/update nonces
    accounts: HashMap<&'a PublicKey, Account<'a>>,
    // Current stable topoheight of the snapshot
    stable_topoheight: TopoHeight,
    // Current topoheight of the snapshot
    topoheight: TopoHeight,
    // All contracts updated
    contracts: HashMap<&'a Hash, (VersionedState, Option<Cow<'a, Module>>)>,
    // Block header version
    block_version: BlockVersion,
    // All gas fees tracked
    gas_fee: u64
}

impl<'a, S: Storage> ChainState<'a, S> {
    fn with(
        storage: StorageReference<'a, S>,
        environment: &'a Environment,
        stable_topoheight: TopoHeight,
        topoheight: TopoHeight,
        block_version: BlockVersion,
    ) -> Self {
        Self {
            storage,
            environment,
            receiver_balances: HashMap::new(),
            accounts: HashMap::new(),
            stable_topoheight,
            topoheight,
            contracts: HashMap::new(),
            block_version,
            gas_fee: 0
        }
    }

    pub fn new(storage: &'a S, environment: &'a Environment, stable_topoheight: TopoHeight, topoheight: TopoHeight, block_version: BlockVersion) -> Self {
        Self::with(
            StorageReference::Immutable(storage),
            environment,
            stable_topoheight,
            topoheight,
            block_version
        )
    }

    // Get all the gas fees
    pub fn get_gas_fee(&self) -> u64 {
        self.gas_fee
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
    async fn create_sender_echange(storage: &S, key: &'a PublicKey, asset: &'a Hash, current_topoheight: TopoHeight, reference: &Reference) -> Result<Echange, BlockchainError> {
        let (use_output_balance, new_version, version) = super::search_versioned_balance_for_reference(storage, key, asset, current_topoheight, reference).await?;
        Ok(Echange::new(use_output_balance, new_version,  version))
    }

    // Create a sender account by fetching its nonce and create a empty HashMap for balances,
    // those will be fetched lazily
    async fn create_sender_account(key: &PublicKey, storage: &S, topoheight: TopoHeight) -> Result<Account<'a>, BlockchainError> {
        let (topo, mut version) = storage
            .get_nonce_at_maximum_topoheight(key, topoheight).await?
            .ok_or_else(|| BlockchainError::AccountNotFound(key.as_address(storage.is_mainnet())))?;
        version.set_previous_topoheight(Some(topo));

        let multisig = storage.get_multisig_at_maximum_topoheight_for(key, topoheight).await?
            .map(|(topo, multisig)| multisig.take().map(|m| (VersionedState::FetchedAt(topo), Some(m.into_owned()))))
            .flatten();

        Ok(Account {
            nonce: version,
            assets: HashMap::new(),
            multisig
        })
    }

    // Retrieve the receiver balance of an account
    // This is mostly the final balance where everything is added (outputs and inputs)
    async fn internal_get_receiver_balance<'b>(&'b mut self, key: Cow<'a, PublicKey>, asset: Cow<'a, Hash>) -> Result<&'b mut Ciphertext, BlockchainError> {
        match self.receiver_balances.entry(key.clone()).or_insert_with(HashMap::new).entry(asset.clone()) {
            Entry::Occupied(o) => Ok(o.into_mut().get_mut_balance().computable()?),
            Entry::Vacant(e) => {
                let version = self.storage.get_new_versioned_balance(&key, &asset, self.topoheight).await?;
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

    // Get or create account for sender
    async fn get_internal_account(&mut self, key: &'a PublicKey) -> Result<&mut Account<'a>, BlockchainError> {
        match self.accounts.entry(key) {
            Entry::Occupied(o) => Ok(o.into_mut()),
            Entry::Vacant(e) => {
                let account = Self::create_sender_account(key, &self.storage, self.topoheight).await?;
                Ok(e.insert(account))
            }
        }
    }

    // Retrieve the account nonce
    // Only sender accounts should be used here
    async fn internal_get_account_nonce(&mut self, key: &'a PublicKey) -> Result<Nonce, BlockchainError> {
        self.get_internal_account(key).await.map(|a| a.nonce.get_nonce())
    }

    // Update the account nonce
    // Only sender accounts should be used here
    // For each TX, we must update the nonce by one
    async fn internal_update_account_nonce(&mut self, account: &'a PublicKey, new_nonce: Nonce) -> Result<(), BlockchainError> {
        trace!("Updating nonce for {} to {} at topoheight {}", account.as_address(self.storage.is_mainnet()), new_nonce, self.topoheight);
        let account = self.get_internal_account(account).await?;
        account.nonce.set_nonce(new_nonce);
        Ok(())
    }

    // Search for a contract versioned state
    // if not found, fetch it from the storage
    // if not found in storage, create a new one
    async fn internal_get_versioned_contract(&mut self, hash: &'a Hash) -> Result<&mut (VersionedState, Option<Cow<'a, Module>>), BlockchainError> {
        match self.contracts.entry(hash) {
            Entry::Occupied(o) => Ok(o.into_mut()),
            Entry::Vacant(e) => {
                let contract = self.storage.get_contract_at_maximum_topoheight_for(hash, self.topoheight).await?
                    .map(|(topo, contract)| (VersionedState::FetchedAt(topo), contract.take()))
                    .unwrap_or((VersionedState::New, None));

                Ok(e.insert(contract))
            }
        }
    }

    // Load a contract from the storage if its not already loaded
    async fn load_versioned_contract(&mut self, hash: &'a Hash) -> Result<(), BlockchainError> {
        trace!("Loading contract {} at topoheight {}", hash, self.topoheight);
        if !self.contracts.contains_key(hash) {
            let contract = self.storage.get_contract_at_maximum_topoheight_for(hash, self.topoheight).await?
                .map(|(topo, contract)| (VersionedState::FetchedAt(topo), contract.take()))
                .unwrap_or((VersionedState::New, None));

            self.contracts.insert(hash, contract);
        }

        Ok(())
    }

    // Get the contract module from our cache
    async fn internal_get_contract_module(&self, hash: &Hash) -> Result<&Module, BlockchainError> {
        trace!("Getting contract module {}", hash);
        self.contracts.get(hash)
            .ok_or_else(|| BlockchainError::ContractNotFound(hash.clone()))
            .and_then(|(_, module)| module.as_ref().map(|m| m.as_ref()).ok_or_else(|| BlockchainError::ContractNotFound(hash.clone())))
    }

    // Reward a miner for the block mined
    pub async fn reward_miner(&mut self, miner: &'a PublicKey, reward: u64) -> Result<(), BlockchainError> {
        debug!("Rewarding miner {} with {} XEL at topoheight {}", miner.as_address(self.storage.is_mainnet()), format_xelis(reward), self.topoheight);
        let miner_balance = self.internal_get_receiver_balance(Cow::Borrowed(miner), Cow::Borrowed(&XELIS_ASSET)).await?;
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
        super::pre_verify_tx(self.storage.as_ref(), tx, self.stable_topoheight, self.topoheight, self.get_block_version()).await
    }

    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance<'b>(
        &'b mut self,
        account: Cow<'a, PublicKey>,
        asset: Cow<'a, Hash>,
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
        let account = self.get_internal_account(account).await?;
        if let Some((state, multisig)) = account.multisig.as_mut() {
            state.mark_updated();
            *multisig = if payload.is_delete() { None } else { Some(payload.clone()) };
        } else {
            let multisig = if payload.is_delete() { None } else { Some(payload.clone()) };
            account.multisig = Some((VersionedState::New, multisig));
        }

        Ok(())
    }

    /// Get the multisig state for an account
    /// If the account is not a multisig account, return None
    async fn get_multisig_state(
        &mut self,
        account: &'a PublicKey
    ) -> Result<Option<&MultiSigPayload>, BlockchainError> {
        let account = self.get_internal_account(account).await?;
        Ok(account.multisig.as_ref().and_then(|(_, multisig)| multisig.as_ref()))
    }

    /// Get the contract environment
    async fn get_environment(&mut self) -> Result<&Environment, BlockchainError> {
        Ok(self.environment)
    }

    /// Set the contract module
    async fn set_contract_module(
        &mut self,
        hash: &'a Hash,
        module: &'a Module
    ) -> Result<(), BlockchainError> {
        let (state, m) = self.internal_get_versioned_contract(&hash).await?;
        if !state.is_new() {
            return Err(BlockchainError::ContractAlreadyExists);
        }

        state.mark_updated();
        *m = Some(Cow::Borrowed(module));

        Ok(())
    }

    async fn load_contract_module(
        &mut self,
        hash: &'a Hash
    ) -> Result<(), BlockchainError> {
        self.load_versioned_contract(hash).await
    }

    /// Get the contract module with the environment
    async fn get_contract_module_with_environment(
        &self,
        hash: &'a Hash
    ) -> Result<(&Module, &Environment), BlockchainError> {
        let module = self.internal_get_contract_module(hash).await?;
        Ok((module, self.environment))
    }
}