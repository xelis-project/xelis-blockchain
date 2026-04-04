use std::collections::HashMap;

use anyhow::Context;
use curve25519_dalek::Scalar;

use crate::{
    account::{CiphertextCache, Nonce},
    api::DataElement,
    config::XELIS_ASSET,
    crypto::{
        elgamal::Ciphertext,
        Address,
        Hash,
        KeyPair,
        PublicKey,
        proofs::G
    },
    transaction::{
        builder::{
            AccountState,
            FeeBuilder,
            FeeHelper,
            TransactionBuilder,
            TransactionTypeBuilder,
            TransferBuilder,
        },
        Reference,
        Transaction,
        TxVersion,
    },
};

mod chain_state;
mod provider;

pub use chain_state::*;
pub use provider::*;

#[derive(Clone)]
pub struct TrackedBalance {
    pub ciphertext: CiphertextCache,
    pub balance: u64,
}

#[derive(Clone)]
pub struct TrackedAccount {
    pub balances: HashMap<Hash, TrackedBalance>,
    pub keypair: KeyPair,
    pub nonce: Nonce,
}

impl TrackedAccount {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
            keypair: KeyPair::new(),
            nonce: 0,
        }
    }

    pub fn set_balance(&mut self, asset: Hash, balance: u64) {
        let ciphertext = self.keypair.get_public_key().encrypt(balance);
        self.balances.insert(
            asset,
            TrackedBalance {
                balance,
                ciphertext: CiphertextCache::Decompressed(None, ciphertext),
            },
        );
    }

    pub fn set_balance_with_ciphertext(&mut self, asset: Hash, balance: u64, ciphertext: Ciphertext) {
        self.balances.insert(
            asset,
            TrackedBalance {
                balance,
                ciphertext: CiphertextCache::Decompressed(None, ciphertext),
            },
        );
    }

    pub fn address(&self) -> Address {
        self.keypair.get_public_key().to_address(false)
    }

    /// Get the encrypted balance for this account's asset
    pub fn get_balance(&self, asset: &Hash) -> anyhow::Result<u64> {
        self.balances
            .get(asset)
            .map(|b| b.balance)
            .context("balance not found")
    }

    /// Get the serialized public key for this account
    pub fn get_public_key(&self) -> PublicKey {
        self.keypair.get_public_key().compress()
    }

    /// Validate that this account's balance matches expected value
    /// Returns error if points don't match (balance was corrupted or modified)
    pub fn assert_balance(&self, expected: u64) -> anyhow::Result<()> {
        let tracked = self
            .balances
            .get(&XELIS_ASSET)
            .context("tracked account is missing XELIS balance")?;

        let ciphertext = tracked
            .ciphertext
            .clone()
            .take_ciphertext()
            .context("failed to decode tracked ciphertext")?;

        let point = self.keypair.decrypt_to_point(&ciphertext);
        let expected_point = Scalar::from(expected) * &(*G);

        anyhow::ensure!(
            point == expected_point,
            "balance mismatch: expected {}, but got different decrypted point",
            expected
        );

        Ok(())
    }
}

pub struct TrackedAccountState {
    pub balances: HashMap<Hash, TrackedBalance>,
    pub reference: Reference,
    pub nonce: Nonce,
}

pub fn create_transfer_tx_for_account(
    account: &mut TrackedAccount,
    destination: Address,
    amount: u64,
    extra_data: Option<DataElement>,
    version: TxVersion,
    reference: Reference,
) -> anyhow::Result<Transaction> {
    let mut state = TrackedAccountState {
        balances: account.balances.clone(),
        nonce: account.nonce,
        reference,
    };

    let data = TransactionTypeBuilder::Transfers(vec![TransferBuilder {
        amount,
        destination,
        asset: XELIS_ASSET,
        extra_data,
        encrypt_extra_data: true,
    }]);

    let builder = TransactionBuilder::new(
        version,
        account.keypair.get_public_key().compress(),
        None,
        data,
        FeeBuilder::default(),
    );

    let tx = builder.build(&mut state, &account.keypair)?;
    account.balances = state.balances;
    account.nonce = state.nonce;

    Ok(tx)
}

impl FeeHelper for TrackedAccountState {
    type Error = anyhow::Error;

    fn get_max_fee(&self, fee: u64) -> u64 {
        fee * 2
    }

    fn account_exists(&self, _: &PublicKey) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

impl AccountState for TrackedAccountState {
    fn is_mainnet(&self) -> bool {
        false
    }

    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error> {
        self.balances
            .get(asset)
            .map(|balance| balance.balance)
            .context("account balance not found")
    }

    fn get_account_ciphertext(&self, asset: &Hash) -> Result<CiphertextCache, Self::Error> {
        self.balances
            .get(asset)
            .map(|balance| balance.ciphertext.clone())
            .context("account ciphertext not found")
    }

    fn get_reference(&self) -> Reference {
        self.reference.clone()
    }

    fn update_account_balance(
        &mut self,
        asset: &Hash,
        balance: u64,
        ciphertext: Ciphertext,
    ) -> Result<(), Self::Error> {
        self.balances.insert(
            asset.clone(),
            TrackedBalance {
                balance,
                ciphertext: CiphertextCache::Decompressed(None, ciphertext),
            },
        );
        Ok(())
    }

    fn get_nonce(&self) -> Result<Nonce, Self::Error> {
        Ok(self.nonce)
    }

    fn update_nonce(&mut self, new_nonce: Nonce) -> Result<(), Self::Error> {
        self.nonce = new_nonce;
        Ok(())
    }
}
