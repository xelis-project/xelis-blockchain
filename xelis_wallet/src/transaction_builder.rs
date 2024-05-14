use std::collections::{HashMap, HashSet};
use xelis_common::{
    account::CiphertextCache,
    crypto::{elgamal::Ciphertext, Hash, PublicKey},
    transaction::{builder::{AccountState, FeeHelper}, Reference}
};
use crate::{error::WalletError, storage::{Balance, EncryptedStorage, TxCache}};

// State used to estimate fees for a transaction
// Because fees can be higher if a destination account is not registered
// We need to give this information during the estimation of fees
pub struct EstimateFeesState {
    // this is containing the registered keys that we are aware of
    registered_keys: HashSet<PublicKey>
}

impl EstimateFeesState {
    pub fn new() -> Self {
        Self {
            registered_keys: HashSet::new()
        }
    }

    pub fn set_registered_keys(&mut self, registered_keys: HashSet<PublicKey>) {
        self.registered_keys = registered_keys;
    }

    pub fn add_registered_key(&mut self, key: PublicKey) {
        self.registered_keys.insert(key);
    }
}

impl FeeHelper for EstimateFeesState {
    type Error = WalletError;

    fn account_exists(&self, key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(self.registered_keys.contains(key))
    }
}

// State used to build a transaction
// It contains the balances of the wallet and the registered keys
pub struct TransactionBuilderState {
    inner: EstimateFeesState,
    mainnet: bool,
    balances: HashMap<Hash, Balance>,
    reference: Reference,
    nonce: u64,
    tx_hash_built: Option<Hash>
}

impl TransactionBuilderState {
    pub fn new(mainnet: bool, reference: Reference, nonce: u64) -> Self {
        Self {
            inner: EstimateFeesState {
                registered_keys: HashSet::new(),
            },
            mainnet,
            balances: HashMap::new(),
            reference,
            nonce,
            tx_hash_built: None
        }
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

    pub async fn apply_changes(&mut self, storage: &mut EncryptedStorage) -> Result<(), WalletError> {
        let last_tx_hash_created = self.tx_hash_built.take().ok_or(WalletError::TxNotBuilt)?;
        for (asset, balance) in self.balances.drain() {
            storage.set_unconfirmed_balance_for(asset, balance).await?;
        }

        storage.set_tx_cache(TxCache {
            reference: self.reference.clone(),
            nonce: self.nonce,
            last_tx_hash_created,
        });

        Ok(())
    }
}

impl FeeHelper for TransactionBuilderState {
    type Error = WalletError;

    fn account_exists(&self, key: &PublicKey) -> Result<bool, Self::Error> {
        self.inner.account_exists(key)
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
        self.balances.insert(asset.clone(), Balance {
            amount: new_balance,
            ciphertext: CiphertextCache::Decompressed(ciphertext)
        });
        Ok(())
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