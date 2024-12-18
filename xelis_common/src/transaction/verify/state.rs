use std::borrow::Cow;

use async_trait::async_trait;
use xelis_vm::{Environment, Module};
use crate::{
    account::Nonce,
    block::{Block, BlockVersion},
    contract::ContractOutput,
    crypto::{
        elgamal::{
            Ciphertext,
            CompressedPublicKey
        },
        Hash
    },
    transaction::{
        MultiSigPayload,
        Reference,
        Transaction
    }
};

/// This trait is used by the batch verification function.
/// It is intended to represent a virtual snapshot of the current blockchain
/// state, where the transactions can get applied in order.
#[async_trait]
pub trait BlockchainVerificationState<'a, E> {
    // This is giving a "implementation is not general enough"
    // We replace it by a generic type in the trait definition
    // See: https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=aaa6065daaab514e638b2333703765c7
    // type Error;

    /// Pre-verify the TX
    async fn pre_verify_tx<'b>(
        &'b mut self,
        tx: &Transaction,
    ) -> Result<(), E>;

    /// Get the balance ciphertext for a receiver account
    async fn get_receiver_balance<'b>(
        &'b mut self,
        account: Cow<'a, CompressedPublicKey>,
        asset: Cow<'a, Hash>,
    ) -> Result<&'b mut Ciphertext, E>;

    /// Get the balance ciphertext used for verification of funds for the sender account
    async fn get_sender_balance<'b>(
        &'b mut self,
        account: &'a CompressedPublicKey,
        asset: &'a Hash,
        reference: &Reference,
    ) -> Result<&'b mut Ciphertext, E>;

    /// Apply new output to a sender account
    async fn add_sender_output(
        &mut self,
        account: &'a CompressedPublicKey,
        asset: &'a Hash,
        output: Ciphertext,
    ) -> Result<(), E>;

    /// Get the nonce of an account
    async fn get_account_nonce(
        &mut self,
        account: &'a CompressedPublicKey
    ) -> Result<Nonce, E>;

    /// Apply a new nonce to an account
    async fn update_account_nonce(
        &mut self,
        account: &'a CompressedPublicKey,
        new_nonce: Nonce
    ) -> Result<(), E>;

    /// Get the block version in which TX is executed
    fn get_block_version(&self) -> BlockVersion;

    /// Set the multisig state for an account
    async fn set_multisig_state(
        &mut self,
        account: &'a CompressedPublicKey,
        config: &MultiSigPayload
    ) -> Result<(), E>;

    /// Set the multisig state for an account
    async fn get_multisig_state(
        &mut self,
        account: &'a CompressedPublicKey
    ) -> Result<Option<&MultiSigPayload>, E>;

    /// Get the contract environment
    async fn get_contract_environment(&mut self) -> Result<&Environment, E>;

    /// Set the contract module
    async fn set_contract_module(
        &mut self,
        hash: &'a Hash,
        module: &'a Module
    ) -> Result<(), E>;

    /// Load in the cache the contract module
    /// This is called before `get_contract_module_with_environment`
    async fn load_contract_module(
        &mut self,
        hash: &'a Hash
    ) -> Result<(), E>;

    /// Get the contract module
    async fn get_contract_module_with_environment(
        &self,
        hash: &'a Hash
    ) -> Result<(&Module, &Environment), E>;
}

#[async_trait]
pub trait BlockchainApplyState<'a, E>: BlockchainVerificationState<'a, E> {
    /// Add burned XELIS
    async fn add_burned_coins(&mut self, amount: u64) -> Result<(), E>;

    /// Add fee XELIS
    async fn add_gas_fee(&mut self, amount: u64) -> Result<(), E>;

    /// Get the hash of the block
    fn get_block_hash(&self) -> &Hash;

    /// Get the block
    fn get_block(&self) -> &Block;

    /// Is mainnet network
    fn is_mainnet(&self) -> bool;

    /// Track the contract outputs
    async fn add_contract_output(
        &mut self,
        contract: &'a Hash,
        tx_hash: &'a Hash,
        output: ContractOutput
    ) -> Result<(), E>;

    /// Track the invoke contract result
    async fn add_contract_result(
        &mut self,
        contract: &'a Hash,
        tx_hash: &'a Hash,
        result: Option<u64>
    ) -> Result<(), E>;
}