use std::{borrow::Cow, collections::HashMap};

use async_trait::async_trait;
use indexmap::IndexMap;
use xelis_vm::{Environment, Module};
use crate::{
    account::Nonce,
    block::BlockVersion,
    contract::{
        vm::ContractCaller,
        AssetChanges,
        ChainState,
        ContractCache,
        ContractEventTracker,
        ContractLog,
        ContractProvider,
        InterContractPermission,
        ContractMetadata,
        ScheduledExecution,
        ContractModule,
        ContractVersion
    },
    crypto::{
        elgamal::{
            Ciphertext,
            CompressedPublicKey
        },
        Hash
    },
    transaction::{
        ContractDeposit,
        MultiSigPayload,
        Reference,
        Transaction
    },
    versioned_type::VersionedState
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

    /// Verify the TX fee and returns, if required, how much we should refund from
    /// `fee_limit` (left over of fees)
    async fn handle_tx_fee<'b>(&'b mut self, tx: &Transaction, tx_hash: &Hash) -> Result<u64, E>;

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

    /// Get the environment
    /// Returns an error if the environment is not found or not compatible
    async fn get_environment(&mut self, version: ContractVersion) -> Result<&Environment<ContractMetadata>, E>;

    /// Set the contract module
    async fn set_contract_module(
        &mut self,
        hash: &'a Hash,
        module: &'a ContractModule,
    ) -> Result<(), E>;

    /// Load in the cache the contract module
    /// This is called before `get_contract_module_with_environment`
    /// Returns true if the module is available
    async fn load_contract_module(
        &mut self,
        hash: Cow<'a, Hash>
    ) -> Result<bool, E>;

    /// Get the contract module with the environment
    /// This is used to verify that all parameters are correct
    async fn get_contract_module_with_environment(
        &self,
        hash: &'a Hash
    ) -> Result<(&Module, &Environment<ContractMetadata>), E>;
}

pub struct ContractEnvironment<'a, P: ContractProvider> {
    // Environment with the embed stdlib
    pub environment: &'a Environment<ContractMetadata>,
    // Module to execute
    pub module: &'a Module,
    // Version of the contract
    pub version: ContractVersion,
    // Provider for the contract
    pub provider: &'a P,
}

#[async_trait]
pub trait BlockchainContractState<'a, P: ContractProvider, E> {
    /// Track the contract logs
    async fn set_contract_logs(
        &mut self,
        caller: ContractCaller<'a>,
        logs: Vec<ContractLog>
    ) -> Result<(), E>;

    /// Get the contract environment
    /// Implementation should take care of deposits by applying them
    /// to the chain state
    async fn get_contract_environment_for<'b>(
        &'b mut self,
        contract: Cow<'b, Hash>,
        deposits: Option<&'b IndexMap<Hash, ContractDeposit>>,
        tx_hash: ContractCaller<'b>,
        permission: Cow<'b, InterContractPermission>,
    ) -> Result<(ContractEnvironment<'b, P>, ChainState<'b>), E>;

    /// Set the updated contract caches
    /// This is used to update the caches after the contract execution
    /// Even if the execution failed, the caches should be updated
    async fn set_modules_cache(
        &mut self,
        modules: HashMap<Hash, Option<ContractModule>>,
    ) -> Result<(), E>;

    /// Merge the contract cache with the stored one
    async fn merge_contract_changes(
        &mut self,
        caches: HashMap<Hash, ContractCache>,
        tracker: ContractEventTracker,
        assets: HashMap<Hash, Option<AssetChanges>>,
        executions_block_end: IndexMap<Hash, ScheduledExecution>,
        extra_gas_fee: u64,
    ) -> Result<(), E>;

    /// Retrieve the contract balance used to pay gas
    async fn get_contract_balance_for_gas<'b>(
        &'b mut self,
        contract: &'b Hash,
    ) -> Result<&'b mut (VersionedState, u64), E>;

    /// Remove the contract module
    /// This will mark the contract
    /// as a None version
    async fn remove_contract_module(
        &mut self,
        hash: &'a Hash
    ) -> Result<(), E>;
}

#[async_trait]
pub trait BlockchainApplyState<'a, P: ContractProvider, E>: BlockchainVerificationState<'a, E> + BlockchainContractState<'a, P, E> {
    /// Add burned XELIS
    async fn add_burned_coins(&mut self, asset: &Hash, amount: u64) -> Result<(), E>;

    /// Add fee XELIS
    async fn add_gas_fee(&mut self, amount: u64) -> Result<(), E>;

    /// Add burned XELIS fee
    async fn add_burned_fee(&mut self, amount: u64) -> Result<(), E>;

    /// Is mainnet network
    fn is_mainnet(&self) -> bool;
}