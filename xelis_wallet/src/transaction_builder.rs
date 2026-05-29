use std::{collections::{HashMap, HashSet}, ops::{Deref, DerefMut}};
use log::{debug, trace};
use xelis_common::{
    account::CiphertextCache,
    crypto::{elgamal::Ciphertext, Hash, Hashable, PublicKey},
    transaction::{builder::{AccountState, FeeHelper}, Reference, Transaction}
};
use crate::{error::WalletError, storage::{Balance, EncryptedStorage, TxCache}};

// State used to estimate fees for a transaction
// Because fees can be higher if a destination account is not registered
// We need to give this information during the estimation of fees
pub struct EstimateFeesState {
    // this is containing the registered keys that we are aware of
    registered_keys: HashSet<PublicKey>,
    base_fee: Option<u64>,
}

impl EstimateFeesState {
    pub fn new() -> Self {
        Self {
            registered_keys: HashSet::new(),
            base_fee: None
        }
    }

    pub fn set_registered_keys(&mut self, registered_keys: HashSet<PublicKey>) {
        self.registered_keys = registered_keys;
    }

    pub fn add_registered_key(&mut self, key: PublicKey) {
        self.registered_keys.insert(key);
    }

    pub fn set_base_fee(&mut self, base_fee: impl Into<Option<u64>>) {
        self.base_fee = base_fee.into();
    }
}

impl FeeHelper for EstimateFeesState {
    type Error = WalletError;

    fn account_exists(&self, key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(self.registered_keys.contains(key))
    }

    fn get_base_fee(&self) -> Option<u64> {
        self.base_fee
    }
}

// State used to build a transaction
// It contains the balances of the wallet and the registered keys
pub struct TransactionBuilderState {
    // Inner state used to estimate fees
    inner: EstimateFeesState,
    // If we are on mainnet or not
    mainnet: bool,
    // Balances of the wallet
    balances: HashMap<Hash, Balance>,
    // Reference at which the transaction is built
    reference: Reference,
    // Nonce of the transaction
    nonce: u64,
    // The hash of the transaction that has been built
    tx_hash_built: Option<Hash>,
    // The stable topoheight detected during the TX building
    // This is used to update the last coinbase reward topoheight
    stable_topoheight: Option<u64>,
    // Fee max to pay
    fee_limit: Option<u64>,
}

impl TransactionBuilderState {
    pub fn new(mainnet: bool, reference: Reference, nonce: u64, fee_limit: Option<u64>) -> Self {
        Self {
            inner: EstimateFeesState::new(),
            mainnet,
            balances: HashMap::new(),
            reference,
            nonce,
            fee_limit,
            tx_hash_built: None,
            stable_topoheight: None,
        }
    }

    pub fn get_reference(&self) -> &Reference {
        &self.reference
    }

    pub fn set_reference(&mut self, reference: Reference) {
        self.reference = reference;
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn has_balance_for(&self, asset: &Hash) -> bool {
        self.balances.contains_key(asset)
    }

    pub async fn from_tx(storage: &EncryptedStorage, transaction: &Transaction, mainnet: bool) -> Result<Self, WalletError> {
        let mut state = Self::new(mainnet, transaction.get_reference().clone(), transaction.get_nonce(), Some(transaction.get_fee_limit()));
        let ciphertexts = transaction.get_expected_sender_outputs()?;

        for (asset, ct) in ciphertexts {
            let (mut balance, _) = storage.get_unconfirmed_balance_for(asset).await?;
            let balance_ct = balance.ciphertext.computable()?;

            *balance_ct -= ct;
            state.add_balance(asset.clone(), balance);
        }

        state.set_tx_hash_built(transaction.hash());

        Ok(state)
    }

    pub fn set_balances(&mut self, balances: HashMap<Hash, Balance>) {
        self.balances = balances;
    }

    pub fn add_balance(&mut self, asset: Hash, balance: Balance) {
        self.balances.insert(asset, balance);
    }

    pub fn set_registered_keys(&mut self, registered_keys: HashSet<PublicKey>) {
        self.inner.registered_keys = registered_keys;
    }

    pub fn add_registered_key(&mut self, key: PublicKey) {
        self.inner.registered_keys.insert(key);
    }

    // This must be called once the TX has been built
    pub fn set_tx_hash_built(&mut self, tx_hash: Hash) {
        self.tx_hash_built = Some(tx_hash);
    }

    // Set the stable topoheight detected during the TX building
    pub fn set_stable_topoheight(&mut self, stable_topoheight: u64) {
        self.stable_topoheight = Some(stable_topoheight);
    }

    // Apply the changes to the storage
    pub async fn apply_changes(&mut self, storage: &mut EncryptedStorage) -> Result<(), WalletError> {
        trace!("Applying changes to storage");

        storage.set_tx_cache(TxCache {
            reference: self.reference.clone(),
            nonce: self.nonce,
            last_tx_hash_created: self.tx_hash_built.take(),
            assets: self.balances.keys().cloned().collect(),
        });

        for (asset, balance) in self.balances.drain() {
            debug!("Setting balance for asset {} to {} ({})", asset, balance.amount, balance.ciphertext);
            storage.set_unconfirmed_balance_for(asset, balance).await?;
        }

        // Lets verify if the last unstable balance topoheight is still valid
        if let Some(stable_topoheight) = self.stable_topoheight {
            if storage.get_last_coinbase_topoheight().is_some_and(|h| h <= stable_topoheight) {
                storage.set_last_coinbase_topoheight(None)?;
            }
        }

        Ok(())
    }
}

impl FeeHelper for TransactionBuilderState {
    type Error = WalletError;

    fn get_max_fee(&self, fee: u64) -> u64 {
        self.fee_limit.unwrap_or(fee)
    }

    fn account_exists(&self, key: &PublicKey) -> Result<bool, Self::Error> {
        self.inner.account_exists(key)
    }

    fn get_base_fee(&self) -> Option<u64> {
        self.inner.base_fee
    }
}

impl AccountState for TransactionBuilderState {
    fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    fn get_reference(&self) -> Reference {
        self.reference.clone()
    }

    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error> {
        self.balances.get(asset).map(|b| b.amount).ok_or_else(|| WalletError::BalanceNotFound(asset.clone()))
    }

    fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextCache, Self::Error> {
        self.balances.get(asset).map(|b| b.ciphertext.clone()).ok_or_else(|| WalletError::BalanceNotFound(asset.clone()))
    }

    fn update_account_balance(&mut self, asset: &Hash, new_balance: u64, ciphertext: Ciphertext) -> Result<(), Self::Error> {
        self.balances.get_mut(asset)
            .map(|balance| {
                balance.amount = new_balance;
                balance.ciphertext = CiphertextCache::Decompressed(None, ciphertext);
                balance.topoheight = self.reference.topoheight.max(balance.topoheight);

                ()
            })
            .ok_or_else(|| WalletError::BalanceNotFound(asset.clone()))
    }

    fn get_nonce(&self) -> Result<u64, Self::Error> {
        Ok(self.nonce)
    }

    fn update_nonce(&mut self, new_nonce: u64) -> Result<(), Self::Error> {
        self.nonce = new_nonce;
        Ok(())
    }
}

impl AsMut<EstimateFeesState> for TransactionBuilderState {
    fn as_mut(&mut self) -> &mut EstimateFeesState {
        &mut self.inner
    }
}

impl Deref for TransactionBuilderState {
    type Target = EstimateFeesState;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TransactionBuilderState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}