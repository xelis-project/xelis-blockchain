mod opaque;
mod random;
mod contract_log;
mod provider;
mod cache;
mod metadata;
mod scheduled_execution;
mod permission;
mod module;
mod source;
mod error;
mod event_callback;
mod version;
mod chain_state;

#[cfg(test)]
pub mod tests;

pub mod vm;

use std::{
    any::TypeId,
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};
use anyhow::Context as AnyhowContext;
use curve25519_dalek::Scalar;
use indexmap::IndexMap;
use log::{debug, info};
use xelis_builder::{EnvironmentBuilder, xstd::*};
use xelis_vm::{
    VMContext,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    FnType,
    FunctionHandler,
    OpaqueWrapper,
    Primitive,
    SysCallResult,
    Type,
    ValueCell,
    Environment,
};
use crate::{
    account::CiphertextCache,
    block::TopoHeight,
    config::{
        COST_PER_ASSET,
        COST_PER_SCHEDULED_EXECUTION,
        FEE_PER_ACCOUNT_CREATION,
        FEE_PER_BYTE_OF_EVENT_DATA,
        FEE_PER_READ_CONTRACT,
        FEE_PER_STORE_CONTRACT,
        MAX_GAS_USAGE_PER_TX,
        XELIS_ASSET,
        CONTRACT_MAX_PAYLOAD_SIZE,
        CONTRACT_PAYLOAD_FEE_PER_BYTE,
    },
    contract::vm::ContractCaller,
    crypto::{
        proofs::*,
        Address,
        Hash,
        PublicKey,
        Signature
    },
    serializer::Serializer,
    transaction::ContractDeposit,
    versioned::VersionedState
};

pub use random::DeterministicRandom;
pub use contract_log::*;

pub use opaque::*;
pub use provider::*;
pub use cache::*;
pub use metadata::*;
pub use scheduled_execution::*;
pub use permission::*;
pub use module::*;
pub use source::*;
pub use error::*;
pub use event_callback::*;
pub use version::*;
pub use chain_state::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutput {
    // The destination key for the transfer
    pub destination: PublicKey,
    // The amount to transfer
    pub amount: u64,
    // The asset to transfer
    pub asset: Hash,
}

pub type ContractEnvironments = HashMap<ContractVersion, Arc<Environment<ContractMetadata>>>;

// Callback event to be processed after the execution
#[derive(Debug, Clone)]
pub struct CallbackEvent {
    // Contract from which it is triggered
    pub contract: Hash,
    // Event id
    pub event_id: u64,
    // Params to call the callback
    pub params: Vec<ValueCell>,
}

macro_rules! async_handler {
    ($func: expr) => {
        move |a, b, c, d| {
          Box::pin($func(a, b, c, d))
        }
    };
}

// Build the environment for the contract
pub fn build_environment<P: for<'ty> ContractProvider<'ty>>(version: ContractVersion) -> EnvironmentBuilder<'static, ContractMetadata> {
    debug!("Building environment for contract");

    let mut env = EnvironmentBuilder::new();
    array::register(&mut env);
    bytes::register(&mut env);
    optional::register(&mut env);
    string::register(&mut env);
    integer::register(&mut env);
    range::register(&mut env);
    map::register(&mut env);
    math::register(&mut env);
    register_defaults(&mut env);

    if version >= ContractVersion::V1 {
        iterator::register(&mut env);
    }

    // Register the constructor hook
    env.register_hook("constructor", vec![], Some(Type::U64));

    env.get_mut_function("println", None)
        .set_on_call(FunctionHandler::Sync(println_fn));

    env.get_mut_function("debug", None)
        .set_on_call(FunctionHandler::Sync(debug_fn));

    // Opaque type but we provide getters
    // All opaque types not allowed as entry input
    let tx_type = Type::Opaque(env.register_opaque::<OpaqueTransaction>("Transaction", false));
    let block_type = Type::Opaque(env.register_opaque::<OpaqueBlock>("Block", false));

    let random_type = Type::Opaque(env.register_opaque::<OpaqueRandom>("Random", false));
    let storage_type = Type::Opaque(env.register_opaque::<OpaqueStorage>("Storage", false));
    let read_only_storage_type = Type::Opaque(env.register_opaque::<OpaqueReadOnlyStorage>("ReadOnlyStorage", false));
    let memory_storage_type = Type::Opaque(env.register_opaque::<OpaqueMemoryStorage>("MemoryStorage", false));
    let asset_type = Type::Opaque(env.register_opaque::<OpaqueAsset>("Asset", false));

    // All others opaque types accepted as input
    let hash_type = Type::Opaque(env.register_opaque::<Hash>("Hash", true));
    let address_type = Type::Opaque(env.register_opaque::<Address>("Address", true));
    let signature_type = Type::Opaque(env.register_opaque::<Signature>("Signature", true));

    // Crypto
    let ciphertext_type = Type::Opaque(env.register_opaque::<CiphertextCache>("Ciphertext", true));
    let ristretto_type = Type::Opaque(env.register_opaque::<OpaqueRistrettoPoint>("RistrettoPoint", true));
    let scalar_type = Type::Opaque(env.register_opaque::<OpaqueScalar>("Scalar", true));
    let transcript_type = Type::Opaque(env.register_opaque::<OpaqueTranscript>("Transcript", false));
    let ct_validity_proof_type = Type::Opaque(env.register_opaque::<CiphertextValidityProof>("CiphertextValidityProof", true));
    let commitment_equality_proof_type = Type::Opaque(env.register_opaque::<CommitmentEqProof>("CommitmentEqualityProof", true));
    let range_proof_type = Type::Opaque(env.register_opaque::<RangeProofWrapper>("RangeProof", true));
    let arbitrary_range_proof_type = Type::Opaque(env.register_opaque::<ArbitraryRangeProof>("ArbitraryRangeProof", true));
    let ownership_proof_type = Type::Opaque(env.register_opaque::<OwnershipProof>("OwnershipProof", true));
    let balance_proof_type = Type::Opaque(env.register_opaque::<BalanceProof>("BalanceProof", true));

    // Misc
    let contract_type = Type::Opaque(env.register_opaque::<OpaqueContract>("Contract", false));
    let scheduled_execution_type = Type::Opaque(env.register_opaque::<OpaqueScheduledExecution>("ScheduledExecution", false));
    let btree_store_type = Type::Opaque(env.register_opaque::<OpaqueBTreeStore>("BTreeStore", false));
    let btree_cursor_type = Type::Opaque(env.register_opaque::<OpaqueBTreeCursor>("BTreeCursor", false));
    let entry_type = Type::Struct(env.register_structure("Entry", [
        ("key", Type::Bytes),
        ("value", Type::Any),
    ]));

    let max_supply_type = Type::Enum(env.register_enum::<3>("MaxSupplyMode", [
        // Unlimited supply
        ("None", vec![]),
        // Minted at asset creation, cannot mint anymore
        ("Fixed", vec![("max_supply", Type::U64)]),
        // allow minting until max supply is reached in circulating supply
        ("Mintable", vec![("max_supply", Type::U64)]),
    ]));

    // See xelis_common::contract::opaque::storage::BTreeSeekBias
    let btree_seek_bias_type = Type::Enum(env.register_enum::<{ BTreeSeekBias::COUNT }>(
        "BTreeSeekBias", 
        BTreeSeekBias::names().map(|v| (v, Vec::<(&str, Type)>::new()))
    ));

    // Transaction
    {
        // Transaction::current()
        env.register_static_function_with_comment(
            "current",
            tx_type.clone(),
            vec![],
            FunctionHandler::Sync(transaction),
            5,
            Some(Type::Optional(Box::new(tx_type.clone()))),
            "Returns the current transaction when execution was started by a transaction."
        );
        env.register_native_function_with_comment(
            "nonce",
            Some(tx_type.clone()),
            vec![],
            FunctionHandler::Sync(transaction_nonce),
            5,
            Some(Type::U64),
            "Returns the transaction nonce."
        );
        env.register_native_function_with_comment(
            "hash",
            Some(tx_type.clone()),
            vec![],
            FunctionHandler::Sync(transaction_hash),
            5,
            Some(hash_type.clone()),
            "Returns the transaction hash."
        );
        env.register_native_function_with_comment(
            "source",
            Some(tx_type.clone()),
            vec![],
            FunctionHandler::Sync(transaction_source),
            5,
            Some(address_type.clone()),
            "Returns the source address of the transaction."
        );
        env.register_native_function_with_comment(
            "fee",
            Some(tx_type.clone()),
            vec![],
            FunctionHandler::Sync(transaction_fee),
            5,
            Some(Type::U64),
            "Returns the transaction fee in atomic units."
        );
        env.register_native_function_with_comment(
            "signature",
            Some(tx_type.clone()),
            vec![],
            FunctionHandler::Sync(transaction_signature),
            5,
            Some(signature_type.clone()),
            "Returns the transaction signature."
        );
    }

    // Block
    {
        // Block::current()
        env.register_static_function_with_comment(
            "current",
            block_type.clone(),
            vec![],
            FunctionHandler::Sync(block_current),
            5,
            Some(block_type.clone()),
            "Returns the current block context."
        );
        env.register_native_function_with_comment(
            "nonce",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_nonce),
            5,
            Some(Type::U64),
            "Returns the block nonce."
        );
        env.register_native_function_with_comment(
            "timestamp",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_timestamp),
            5,
            Some(Type::U64),
            "Returns the block timestamp."
        );
        env.register_native_function_with_comment(
            "height",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_height),
            5,
            Some(Type::U64),
            "Returns the block height."
        );
        env.register_native_function_with_comment(
            "extra_nonce",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_extra_nonce),
            5,
            Some(Type::Bytes),
            "Returns the block extra nonce bytes."
        );
        env.register_native_function_with_comment(
            "hash",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_hash),
            5,
            Some(hash_type.clone()),
            "Returns the block hash."
        );
        env.register_native_function_with_comment(
            "miner",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_miner),
            5,
            Some(address_type.clone()),
            "Returns the miner address for the block."
        );
        env.register_native_function_with_comment(
            "version",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_version),
            5,
            Some(Type::U8),
            "Returns the block version."
        );
        env.register_native_function_with_comment(
            "tips",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_tips),
            5,
            Some(Type::Array(Box::new(hash_type.clone()))),
            "Returns the block tip hashes."
        );
        env.register_native_function_with_comment(
            "transactions_hashes",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_transactions_hashes),
            50,
            Some(Type::Array(Box::new(hash_type.clone()))),
            "Returns the hashes of the transactions included in the block."
        );
        env.register_native_function_with_comment(
            "transactions",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_transactions),
            250,
            Some(Type::Array(Box::new(tx_type.clone()))),
            "Returns the transactions included in the block."
        );
        env.register_native_function_with_comment(
            "transactions_count",
            Some(block_type.clone()),
            vec![],
            FunctionHandler::Sync(block_transactions_count),
            1,
            Some(Type::U32),
            "Returns the number of transactions in the block."
        );
    }

    // Storage
    {
        // Storage::new()
        env.register_static_function_with_comment(
            "new",
            storage_type.clone(),
            vec![],
            FunctionHandler::Sync(storage),
            5,
            Some(storage_type.clone()),
            "Creates a persistent storage handle for the current contract."
        );
        env.register_native_function_with_comment(
            "load",
            Some(storage_type.clone()),
            vec![("key", Type::Any)],
            FunctionHandler::Async(async_handler!(storage_load::<P>)),
            FEE_PER_READ_CONTRACT,
            Some(Type::Optional(Box::new(Type::Any))),
            "Loads a value from contract storage by key."
        );
        env.register_native_function_with_comment(
            "has",
            Some(storage_type.clone()),
            vec![("key", Type::Any)],
            FunctionHandler::Async(async_handler!(storage_has::<P>)),
            FEE_PER_READ_CONTRACT,
            Some(Type::Bool),
            "Returns whether contract storage contains the key."
        );
        env.register_native_function_with_comment(
            "store",
            Some(storage_type.clone()),
            vec![("key", Type::Any), ("value", Type::Any)],
            FunctionHandler::Async(async_handler!(storage_store::<P>)),
            FEE_PER_STORE_CONTRACT,
            Some(Type::Optional(Box::new(Type::Any))),
            "Stores a value in contract storage and returns the previous value, if any."
        );
        env.register_native_function_with_comment(
            "delete",
            Some(storage_type.clone()),
            vec![("key", Type::Any)],
            FunctionHandler::Async(async_handler!(storage_delete::<P>)),
            FEE_PER_STORE_CONTRACT,
            Some(Type::Optional(Box::new(Type::Any))),
            "Deletes a value from contract storage and returns the previous value, if any."
        );
    }

    // Read Only Storage
    {
        // ReadOnlyStorage::new(<hash>)
        env.register_static_function_with_comment(
            "new",
            read_only_storage_type.clone(),
            vec![("contract", hash_type.clone())],
            FunctionHandler::Async(async_handler!(read_only_storage::<P>)),
            15,
            Some(Type::Optional(Box::new(read_only_storage_type.clone()))),
            "Opens read-only storage for another contract by hash, if available."
        );
        env.register_native_function_with_comment(
            "load",
            Some(read_only_storage_type.clone()),
            vec![("key", Type::Any)],
            FunctionHandler::Async(async_handler!(read_only_storage_load::<P>)),
            50,
            Some(Type::Optional(Box::new(Type::Any))),
            "Loads a value from another contract's read-only storage by key."
        );
        env.register_native_function_with_comment(
            "has",
            Some(read_only_storage_type.clone()),
            vec![("key", Type::Any)],
            FunctionHandler::Async(async_handler!(read_only_storage_has::<P>)),
            25,
            Some(Type::Bool),
            "Returns whether another contract's read-only storage contains the key."
        );
    }

    // Memory Storage
    // It is temporary and not persisted in the state
    // Useful for caching data across executions within the same block
    {
        // MemoryStorage::new()
        env.register_static_function_with_comment(
            "new",
            memory_storage_type.clone(),
            vec![("shared", Type::Bool)],
            FunctionHandler::Sync(memory_storage),
            5,
            Some(memory_storage_type.clone()),
            "Creates a temporary memory storage handle, shared or local."
        );
        env.register_native_function_with_comment(
            "load",
            Some(memory_storage_type.clone()),
            vec![("key", Type::Any)],
            FunctionHandler::Sync(memory_storage_load::<P>),
            5,
            Some(Type::Optional(Box::new(Type::Any))),
            "Loads a value from temporary memory storage by key."
        );
        env.register_native_function_with_comment(
            "has",
            Some(memory_storage_type.clone()),
            vec![("key", Type::Any)],
            FunctionHandler::Sync(memory_storage_has::<P>),
            5,
            Some(Type::Bool),
            "Returns whether temporary memory storage contains the key."
        );
        env.register_native_function_with_comment(
            "store",
            Some(memory_storage_type.clone()),
            vec![("key", Type::Any), ("value", Type::Any)],
            FunctionHandler::Sync(memory_storage_store::<P>),
            5,
            Some(Type::Optional(Box::new(Type::Any))),
            "Stores a value in temporary memory storage and returns the previous value, if any."
        );
        env.register_native_function_with_comment(
            "delete",
            Some(memory_storage_type.clone()),
            vec![("key", Type::Any)],
            FunctionHandler::Sync(memory_storage_delete::<P>),
            5,
            Some(Type::Optional(Box::new(Type::Any))),
            "Deletes a value from temporary memory storage and returns the previous value, if any."
        );
    }

    // Address
    {
        env.register_native_function_with_comment(
            "is_mainnet",
            Some(address_type.clone()),
            vec![],
            FunctionHandler::Sync(address_is_mainnet),
            5,
            Some(Type::Bool),
            "Returns whether the address targets mainnet."
        );
        env.register_native_function_with_comment(
            "to_bytes",
            Some(address_type.clone()),
            vec![],
            FunctionHandler::Sync(address_to_bytes),
            5,
            Some(Type::Bytes),
            "Serializes the address to bytes."
        );
        env.register_native_function_with_comment(
            "to_point",
            Some(address_type.clone()),
            vec![],
            FunctionHandler::Sync(address_to_point),
            10,
            Some(ristretto_type.clone()),
            "Returns the address public key as a Ristretto point."
        );
        env.register_native_function_with_comment(
            "to_string",
            Some(address_type.clone()),
            vec![],
            FunctionHandler::Sync(address_to_string),
            100,
            Some(Type::String),
            "Encodes the address as a string."
        );
        env.register_static_function_with_comment(
            "from_string",
            address_type.clone(),
            vec![("address", Type::String)],
            FunctionHandler::Sync(address_from_string),
            350,
            Some(address_type.clone()),
            "Parses an address from its string representation."
        );
        env.register_static_function_with_comment(
            "from_bytes",
            address_type.clone(),
            vec![
                ("bytes", Type::Bytes),
            ],
            FunctionHandler::Sync(address_from_bytes),
            75,
            Some(address_type.clone()),
            "Deserializes an address from bytes."
        );
    }

    // Hash
    {
        env.register_native_function_with_comment(
            "to_bytes",
            Some(hash_type.clone()),
            vec![],
            FunctionHandler::Sync(hash_to_bytes_fn),
            5,
            Some(Type::Bytes),
            "Serializes the hash to bytes."
        );
        env.register_native_function_with_comment(
            "to_array",
            Some(hash_type.clone()),
            vec![],
            FunctionHandler::Sync(hash_to_array_fn),
            5,
            Some(Type::Array(Box::new(Type::U8))),
            "Returns the hash bytes as a u8 array."
        );
        env.register_native_function_with_comment(
            "to_u256",
            Some(hash_type.clone()),
            vec![],
            FunctionHandler::Sync(hash_to_u256_fn),
            5,
            Some(Type::U256),
            "Interprets the hash as a u256 value."
        );
        env.register_native_function_with_comment(
            "to_hex",
            Some(hash_type.clone()),
            vec![],
            FunctionHandler::Sync(hash_to_hex_fn),
            20,
            Some(Type::String),
            "Encodes the hash as a hexadecimal string."
        );
        env.register_static_function_with_comment(
            "from_bytes",
            hash_type.clone(),
            vec![("bytes", Type::Bytes)],
            FunctionHandler::Sync(hash_from_bytes_fn),
            75,
            Some(hash_type.clone()),
            "Creates a hash from bytes."
        );
        env.register_static_function_with_comment(
            "from_array",
            hash_type.clone(),
            vec![("bytes", Type::Array(Box::new(Type::U8)))],
            FunctionHandler::Sync(hash_from_array_fn),
            75,
            Some(hash_type.clone()),
            "Creates a hash from a u8 array."
        );
        env.register_static_function_with_comment(
            "from_u256",
            hash_type.clone(),
            vec![("value", Type::U256)],
            FunctionHandler::Sync(hash_from_u256_fn),
            75,
            Some(hash_type.clone()),
            "Creates a hash from a u256 value."
        );
        env.register_static_function_with_comment(
            "from_hex",
            hash_type.clone(),
            vec![("hex", Type::String)],
            FunctionHandler::Sync(hash_from_hex_fn),
            75,
            Some(hash_type.clone()),
            "Parses a hash from a hexadecimal string."
        );
        env.register_static_function_with_comment(
            "blake3",
            hash_type.clone(),
            vec![("input", Type::Bytes)],
            FunctionHandler::Sync(blake3_fn),
            3000,
            Some(hash_type.clone()),
            "Computes the BLAKE3 hash of the input bytes."
        );
        env.register_static_function_with_comment(
            "sha3",
            hash_type.clone(),
            vec![("input", Type::Bytes)],
            FunctionHandler::Sync(sha3_fn),
            7500,
            Some(hash_type.clone()),
            "Computes the SHA3 hash of the input bytes."
        );
        env.register_static_function_with_comment(
            "zero",
            hash_type.clone(),
            vec![],
            FunctionHandler::Sync(hash_zero_fn),
            1,
            Some(hash_type.clone()),
            "Returns the all-zero hash."
        );
        env.register_static_function_with_comment(
            "max",
            hash_type.clone(),
            vec![],
            FunctionHandler::Sync(hash_max_fn),
            1,
            Some(hash_type.clone()),
            "Returns the maximum hash value."
        );
    }

    // Random number generator
    {
        // Random::new()
        env.register_static_function_with_comment(
            "new",
            random_type.clone(),
            vec![],
            FunctionHandler::Sync(random_fn),
            5,
            Some(random_type.clone()),
            "Creates a deterministic random generator for this execution."
        );
        env.register_native_function_with_comment(
            "next_u8",
            Some(random_type.clone()),
            vec![],
            FunctionHandler::Sync(random_u8),
            5,
            Some(Type::U8),
            "Generates the next deterministic random u8."
        );
        env.register_native_function_with_comment(
            "next_u16",
            Some(random_type.clone()),
            vec![],
            FunctionHandler::Sync(random_u16),
            5,
            Some(Type::U16),
            "Generates the next deterministic random u16."
        );
        env.register_native_function_with_comment(
            "next_u32",
            Some(random_type.clone()),
            vec![],
            FunctionHandler::Sync(random_u32),
            5,
            Some(Type::U32),
            "Generates the next deterministic random u32."
        );
        env.register_native_function_with_comment(
            "next_u64",
            Some(random_type.clone()),
            vec![],
            FunctionHandler::Sync(random_u64),
            5,
            Some(Type::U64),
            "Generates the next deterministic random u64."
        );
        env.register_native_function_with_comment(
            "next_u128",
            Some(random_type.clone()),
            vec![],
            FunctionHandler::Sync(random_u128),
            5,
            Some(Type::U128),
            "Generates the next deterministic random u128."
        );
        env.register_native_function_with_comment(
            "next_u256",
            Some(random_type.clone()),
            vec![],
            FunctionHandler::Sync(random_u256),
            5,
            Some(Type::U256),
            "Generates the next deterministic random u256."
        );
        env.register_native_function_with_comment(
            "next_bool",
            Some(random_type.clone()),
            vec![],
            FunctionHandler::Sync(random_bool),
            5,
            Some(Type::Bool),
            "Generates the next deterministic random boolean."
        );
    }

    // Asset
    {
        env.register_static_function_with_comment(
            "get_by_id",
            asset_type.clone(),
            vec![("id", Type::U64)],
            FunctionHandler::Async(async_handler!(asset_get_by_id::<P>)),
            1000,
            Some(Type::Optional(Box::new(asset_type.clone()))),
            "Returns an asset by local id, if it exists."
        );
        env.register_static_function_with_comment(
            "create",
            asset_type.clone(),
            vec![
                ("id", Type::U64),
                ("name", Type::String),
                ("ticker", Type::String),
                ("decimals", Type::U8),
                ("max_supply", max_supply_type.clone()),
            ],
            FunctionHandler::Async(async_handler!(asset_create::<P>)),
            2500,
            Some(Type::Optional(Box::new(asset_type.clone()))),
            "Creates a new asset owned by the current contract."
        );
        env.register_static_function_with_comment(
            "get_by_hash",
            asset_type.clone(),
            vec![("hash", hash_type.clone())],
            FunctionHandler::Async(async_handler!(asset_get_by_hash::<P>)),
            500,
            Some(Type::Optional(Box::new(asset_type.clone()))),
            "Returns an asset by hash, if it exists."
        );
        env.register_native_function_with_comment(
            "get_max_supply",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_max_supply),
            5,
            Some(Type::Optional(Box::new(Type::U64))),
            "Returns the configured maximum supply for the asset, if any."
        );
        env.register_native_function_with_comment(
            "get_supply",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Async(async_handler!(asset_get_supply::<P>)),
            15,
            Some(Type::U64),
            "Returns the current circulating supply for the asset."
        );
        env.register_native_function_with_comment(
            "get_name",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_name),
            5,
            Some(Type::String),
            "Returns the self-declared asset name."
        );
        env.register_native_function_with_comment(
            "get_ticker",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_ticker),
            5,
            Some(Type::String),
            "Returns the asset ticker."
        );
        env.register_native_function_with_comment(
            "get_hash",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_hash),
            5,
            Some(hash_type.clone()),
            "Returns the asset hash."
        );
        env.register_native_function_with_comment(
            "get_owner",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_owner),
            5,
            Some(Type::Optional(Box::new(hash_type.clone()))),
            "Returns the current owner contract hash for the asset, if any."
        );
        env.register_native_function_with_comment(
            "get_creator_id",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_creator_id),
            5,
            Some(Type::Optional(Box::new(Type::U64))),
            "Returns the creator contract id for the asset, if any."
        );
        env.register_native_function_with_comment(
            "get_creator",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_creator),
            5,
            Some(Type::Optional(Box::new(hash_type.clone()))),
            "Returns the creator contract hash for the asset, if any."
        );
        env.register_native_function_with_comment(
            "mint",
            Some(asset_type.clone()),
            vec![("amount", Type::U64)],
            FunctionHandler::Async(async_handler!(asset_mint::<P>)),
            500,
            Some(Type::Bool),
            "Mints new supply to the current contract when the asset permits it."
        );
        env.register_native_function_with_comment(
            "is_read_only",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_is_read_only),
            5,
            Some(Type::Bool),
            "Returns whether the current contract can only read this asset."
        );
        env.register_native_function_with_comment(
            "is_mintable",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_is_mintable),
            5,
            Some(Type::Bool),
            "Returns whether the asset supply can still be minted."
        );
        env.register_native_function_with_comment(
            "get_contract_hash",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_contract_hash),
            5,
            Some(Type::Optional(Box::new(hash_type.clone()))),
            "Returns the contract hash that owns the asset, if any."
        );
        env.register_native_function_with_comment(
            "get_id",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_contract_id),
            5,
            Some(Type::Optional(Box::new(Type::U64))),
            "Returns the contract id that owns the asset, if any."
        );
        env.register_native_function_with_comment(
            "transfer_ownership",
            Some(asset_type.clone()),
            vec![("contract", hash_type.clone())],
            FunctionHandler::Async(async_handler!(asset_transfer_ownership::<P>)),
            250,
            Some(Type::Bool),
            "Transfers asset ownership to another contract when allowed."
        );
    }

    // Max Supply Mode
    {
        env.register_native_function_with_comment(
            "get_max_supply",
            Some(max_supply_type.clone()),
            vec![],
            FunctionHandler::Sync(max_supply_mode_get_max_supply),
            5,
            Some(Type::Optional(Box::new(Type::U64))),
            "Returns the maximum supply encoded in this mode, if any."
        );

        env.register_native_function_with_comment(
            "is_mintable",
            Some(max_supply_type.clone()),
            vec![],
            FunctionHandler::Sync(max_supply_mode_is_mintable),
            5,
            Some(Type::Bool),
            "Returns whether this max supply mode allows minting."
        );
    }

    // Signature
    {
        env.register_native_function_with_comment(
            "verify",
            Some(signature_type.clone()),
            vec![
                ("data", Type::Bytes),
                ("point", ristretto_type.clone()),
            ],
            FunctionHandler::Sync(signature_verify_fn),
            500,
            Some(Type::Bool),
            "Verifies the signature against the data and public key point."
        );
        env.register_static_function_with_comment(
            "from_bytes",
            signature_type.clone(),
            vec![("bytes", Type::Bytes)],
            FunctionHandler::Sync(signature_from_bytes_fn),
            75,
            Some(signature_type.clone()),
            "Deserializes a signature from bytes."
        );
    }

    // Ciphertext
    {
        env.register_native_function_with_comment(
            "add",
            Some(ciphertext_type.clone()),
            vec![
                ("value", Type::U64)
            ],
            FunctionHandler::Sync(ciphertext_add_plaintext),
            1500,
            None,
            "Adds a plaintext value to the ciphertext in place."
        );
        env.register_native_function_with_comment(
            "sub",
            Some(ciphertext_type.clone()),
            vec![
                ("value", Type::U64)
            ],
            FunctionHandler::Sync(ciphertext_sub_plaintext),
            1500,
            None,
            "Subtracts a plaintext value from the ciphertext in place."
        );
        env.register_native_function_with_comment(
            "mul",
            Some(ciphertext_type.clone()),
            vec![
                ("value", Type::U64)
            ],
            FunctionHandler::Sync(ciphertext_mul_plaintext),
            2000,
            None,
            "Multiplies the ciphertext by a plaintext value in place."
        );
        env.register_native_function_with_comment(
            "div",
            Some(ciphertext_type.clone()),
            vec![
                ("value", Type::U64)
            ],
            FunctionHandler::Sync(ciphertext_div_plaintext),
            7500,
            None,
            "Divides the ciphertext by a plaintext value in place."
        );
        env.register_static_function_with_comment(
            "generate",
            ciphertext_type.clone(),
            vec![
                ("address", address_type.clone()),
                ("amount", Type::U64)
            ],
            FunctionHandler::Sync(ciphertext_generate),
            2500,
            Some(ciphertext_type.clone()),
            "Generates a ciphertext for an address and plaintext amount."
        );

        // commitment
        env.register_native_function_with_comment(
            "commitment",
            Some(ciphertext_type.clone()),
            vec![],
            FunctionHandler::Sync(ciphertext_commitment),
            5,
            Some(ristretto_type.clone()),
            "Returns the ciphertext commitment point."
        );

        // handle
        env.register_native_function_with_comment(
            "handle",
            Some(ciphertext_type.clone()),
            vec![],
            FunctionHandler::Sync(ciphertext_handle),
            5,
            Some(ristretto_type.clone()),
            "Returns the ciphertext handle point."
        );

        // Ciphertext::zero()
        env.register_static_function_with_comment(
            "zero",
            ciphertext_type.clone(),
            vec![],
            FunctionHandler::Sync(ciphertext_zero),
            10,
            Some(ciphertext_type.clone()),
            "Returns a zero ciphertext."
        );
    }

    // RistrettoPoint
    {
        env.register_constant(ristretto_type.clone(), "G", OpaqueRistrettoPoint::Decompressed(None, *G).into(), ristretto_type.clone());
        env.register_constant(ristretto_type.clone(), "H", OpaqueRistrettoPoint::Decompressed(None, *H).into(), ristretto_type.clone());

        // Is Identity
        env.register_native_function_with_comment(
            "is_identity",
            Some(ristretto_type.clone()),
            vec![],
            FunctionHandler::Sync(ristretto_is_identity),
            5,
            Some(Type::Bool),
            "Returns whether the point is the identity."
        );

        // RistrettoPoint::Identity
        env.register_static_function_with_comment(
            "identity",
            ristretto_type.clone(),
            vec![],
            FunctionHandler::Sync(ristretto_identity),
            50,
            Some(ristretto_type.clone()),
            "Returns the identity Ristretto point."
        );

        // P + (s * G)
        env.register_native_function_with_comment(
            "add_scalar",
            Some(ristretto_type.clone()),
            vec![
                ("value", scalar_type.clone())
            ],
            FunctionHandler::Sync(ristretto_add_scalar),
            14_000,
            Some(ristretto_type.clone()),
            "Returns this point plus the scalar multiplied by the base point."
        );
        // P - (s * G)
        env.register_native_function_with_comment(
            "sub_scalar",
            Some(ristretto_type.clone()),
            vec![
                ("value", scalar_type.clone())
            ],
            FunctionHandler::Sync(ristretto_sub_scalar),
            14_000,
            Some(ristretto_type.clone()),
            "Returns this point minus the scalar multiplied by the base point."
        );
        // P + P2
        env.register_native_function_with_comment(
            "add",
            Some(ristretto_type.clone()),
            vec![
                ("value", ristretto_type.clone())
            ],
            FunctionHandler::Sync(ristretto_add),
            5000,
            Some(ristretto_type.clone()),
            "Returns the sum of this point and another point."
        );
        // P - P2
        env.register_native_function_with_comment(
            "sub",
            Some(ristretto_type.clone()),
            vec![
                ("value", ristretto_type.clone())
            ],
            FunctionHandler::Sync(ristretto_sub),
            6000,
            Some(ristretto_type.clone()),
            "Returns this point minus another point."
        );
        // P * s
        env.register_native_function_with_comment(
            "mul_scalar",
            Some(ristretto_type.clone()),
            vec![
                ("value", scalar_type.clone())
            ],
            FunctionHandler::Sync(ristretto_mul_scalar),
            20_000,
            Some(ristretto_type.clone()),
            "Returns this point multiplied by a scalar."
        );
        // P / s (ensure s != 0)
        env.register_native_function_with_comment(
            "div_scalar",
            Some(ristretto_type.clone()),
            vec![
                ("value", scalar_type.clone())
            ],
            FunctionHandler::Sync(ristretto_div_scalar),
            23_000,
            Some(ristretto_type.clone()),
            "Returns this point divided by a non-zero scalar."
        );
        // From bytes
        env.register_static_function_with_comment(
            "from_bytes",
            ristretto_type.clone(),
            vec![("bytes", Type::Bytes)],
            FunctionHandler::Sync(ristretto_from_bytes),
            1500,
            Some(ristretto_type.clone()),
            "Deserializes a Ristretto point from bytes."
        );
        // To bytes
        env.register_native_function_with_comment(
            "to_bytes",
            Some(ristretto_type.clone()),
            vec![],
            FunctionHandler::Sync(ristretto_to_bytes),
            1500,
            Some(Type::Bytes),
            "Serializes the Ristretto point to bytes."
        );
    }

    // Scalar
    {
        env.register_constant(scalar_type.clone(), "ZERO", OpaqueScalar(Scalar::ZERO).into(), scalar_type.clone());
        env.register_constant(scalar_type.clone(), "ONE", OpaqueScalar(Scalar::ONE).into(), scalar_type.clone());

        // From u64
        env.register_static_function_with_comment(
            "from_u64",
            scalar_type.clone(),
            vec![("value", Type::U64)],
            FunctionHandler::Sync(scalar_from_u64),
            25,
            Some(scalar_type.clone()),
            "Creates a scalar from a u64 value."
        );

        // Invert the scalar
        env.register_native_function_with_comment(
            "invert",
            Some(scalar_type.clone()),
            vec![],
            FunctionHandler::Sync(scalar_invert),
            2500,
            Some(scalar_type.clone()),
            "Returns the multiplicative inverse of the scalar."
        );

        // is zero
        env.register_native_function_with_comment(
            "is_zero",
            Some(scalar_type.clone()),
            vec![],
            FunctionHandler::Sync(scalar_is_zero),
            1,
            Some(Type::Bool),
            "Returns whether the scalar is zero."
        );

        // s * G
        env.register_native_function_with_comment(
            "mul_base",
            Some(scalar_type.clone()),
            vec![],
            FunctionHandler::Sync(scalar_mul_base),
            2500,
            Some(ristretto_type.clone()),
            "Returns the scalar multiplied by the base point."
        );
        // s + s2
        env.register_native_function_with_comment(
            "add",
            Some(scalar_type.clone()),
            vec![
                ("value", scalar_type.clone())
            ],
            FunctionHandler::Sync(scalar_add),
            2000,
            Some(scalar_type.clone()),
            "Returns the sum of this scalar and another scalar."
        );
        // s - s2
        env.register_native_function_with_comment(
            "sub",
            Some(scalar_type.clone()),
            vec![
                ("value", scalar_type.clone())
            ],
            FunctionHandler::Sync(scalar_sub),
            2000,
            Some(scalar_type.clone()),
            "Returns this scalar minus another scalar."
        );
        // s * s2
        env.register_native_function_with_comment(
            "mul",
            Some(scalar_type.clone()),
            vec![
                ("value", scalar_type.clone())
            ],
            FunctionHandler::Sync(scalar_mul),
            4000,
            Some(scalar_type.clone()),
            "Returns this scalar multiplied by another scalar."
        );
        // s / s2 (ensure s2 != 0)
        env.register_native_function_with_comment(
            "div",
            Some(scalar_type.clone()),
            vec![
                ("value", scalar_type.clone())
            ],
            FunctionHandler::Sync(scalar_div),
            6000,
            Some(scalar_type.clone()),
            "Returns this scalar divided by a non-zero scalar."
        );
        // From bytes
        env.register_static_function_with_comment(
            "from_bytes",
            scalar_type.clone(),
            vec![("bytes", Type::Bytes)],
            FunctionHandler::Sync(scalar_from_bytes),
            150,
            Some(Type::Optional(Box::new(scalar_type.clone()))),
            "Deserializes a scalar from bytes, if valid."
        );
        // To bytes
        env.register_native_function_with_comment(
            "to_bytes",
            Some(scalar_type.clone()),
            vec![],
            FunctionHandler::Sync(scalar_to_bytes),
            50,
            Some(Type::Bytes),
            "Serializes the scalar to bytes."
        );
    }

    // Transcript
    {
        // Transcript::new()
        env.register_static_function_with_comment(
            "new",
            transcript_type.clone(),
            vec![("label", Type::Bytes)],
            FunctionHandler::Sync(transcript_new),
            500,
            Some(transcript_type.clone()),
            "Creates a transcript with the given label."
        );

        // challenge scalar
        env.register_native_function_with_comment(
            "challenge_scalar",
            Some(transcript_type.clone()),
            vec![("label", Type::Bytes)],
            FunctionHandler::Sync(transcript_challenge_scalar),
            750,
            Some(scalar_type.clone()),
            "Derives a challenge scalar from the transcript with the given label."
        );

        // challenge bytes
        env.register_native_function_with_comment(
            "challenge_bytes",
            Some(transcript_type.clone()),
            vec![
                ("label", Type::Bytes),
                ("n", Type::U32),
            ],
            FunctionHandler::Sync(transcript_challenge_bytes),
            700,
            Some(Type::Bytes),
            "Derives challenge bytes from the transcript with the given label and length."
        );

        // append_message
        env.register_native_function_with_comment(
            "append_message",
            Some(transcript_type.clone()),
            vec![
                ("label", Type::Bytes),
                ("message", Type::Bytes),
            ],
            FunctionHandler::Sync(transcript_append_message),
            500,
            None,
            "Appends labeled bytes to the transcript."
        );

        // Append point
        env.register_native_function_with_comment(
            "append_point",
            Some(transcript_type.clone()),
            vec![
                ("label", Type::Bytes),
                ("point", ristretto_type.clone()),
            ],
            FunctionHandler::Sync(transcript_append_point),
            250,
            None,
            "Appends a labeled Ristretto point to the transcript."
        );
        // Validate and append point
        env.register_native_function_with_comment(
            "validate_and_append_point",
            Some(transcript_type.clone()),
            vec![
                ("label", Type::Bytes),
                ("point", ristretto_type.clone()),
            ],
            FunctionHandler::Sync(transcript_validate_and_append_point),
            250,
            None,
            "Validates and appends a labeled Ristretto point to the transcript."
        );

        // Append scalar
        env.register_native_function_with_comment(
            "append_scalar",
            Some(transcript_type.clone()),
            vec![
                ("label", Type::Bytes),
                ("scalar", scalar_type.clone()),
            ],
            FunctionHandler::Sync(transcript_append_scalar),
            250,
            None,
            "Appends a labeled scalar to the transcript."
        );
    }

    // CiphertextValidityProof
    {
        // verify
        env.register_native_function_with_comment(
            "verify",
            Some(ct_validity_proof_type.clone()),
            vec![
                ("commitment", ristretto_type.clone()),
                ("dest_pubkey", ristretto_type.clone()),
                ("source_pubkey", ristretto_type.clone()),
                ("dest_handle", ristretto_type.clone()),
                ("source_handle", ristretto_type.clone()),
                ("transcript", transcript_type.clone()),
            ],
            FunctionHandler::Sync(ciphertext_validity_proof_verify),
            150_000,
            Some(Type::Bool),
            "Verifies that the ciphertext handles match the commitment and public keys."
        );
    }

    // CommitmentEqProof
    {
        // verify
        env.register_native_function_with_comment(
            "verify",
            Some(commitment_equality_proof_type.clone()),
            vec![
                ("source_pubkey", ristretto_type.clone()),
                ("ciphertext", ciphertext_type.clone()),
                ("commitment", ristretto_type.clone()),
                ("transcript", transcript_type.clone()),
            ],
            FunctionHandler::Sync(commitment_eq_proof_verify),
            150_000,
            Some(Type::Bool),
            "Verifies equality between a ciphertext commitment and a plain commitment."
        );
    }

    // RangeProof
    {
        // verify single
        env.register_native_function_with_comment(
            "verify_single",
            Some(range_proof_type.clone()),
            vec![
                ("commitment", ristretto_type.clone()),
                ("transcript", transcript_type.clone()),
                // Proof bits
                ("n", Type::U8),
            ],
            FunctionHandler::Sync(range_proof_verify_single),
            1_500_000,
            Some(Type::Bool),
            "Verifies a range proof for a single commitment."
        );

        // verify multiple
        env.register_native_function_with_comment(
            "verify_multiple",
            Some(range_proof_type.clone()),
            vec![
                ("commitments", Type::Array(Box::new(ristretto_type.clone()))),
                ("transcript", transcript_type.clone()),
                // Proof bits
                ("n", Type::U8),
            ],
            FunctionHandler::Sync(range_proof_verify_multiple),
            1_515_000,
            Some(Type::Bool),
            "Verifies a range proof for multiple commitments."
        );
    }

    // Arbitrary Range Proof
    {
        // ArbitraryRangeProof::new
        env.register_static_function_with_comment(
            "new",
            arbitrary_range_proof_type.clone(),
            vec![
                ("max_value", Type::U64),
                ("delta_commitment", ristretto_type.clone()),
                ("eq_commitment_proof", commitment_equality_proof_type.clone()),
                ("range_proof", range_proof_type.clone()),
            ],
            FunctionHandler::Sync(arbitrary_range_proof_new),
            500,
            Some(arbitrary_range_proof_type.clone()),
            "Creates an arbitrary range proof wrapper from its components."
        );

        // max_value
        env.register_native_function_with_comment(
            "max_value",
            Some(arbitrary_range_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(arbitrary_range_proof_max_value),
            1,
            Some(Type::U64),
            "Returns the maximum value covered by the arbitrary range proof."
        );

        // delta_commitment
        env.register_native_function_with_comment(
            "delta_commitment",
            Some(arbitrary_range_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(arbitrary_range_proof_delta_commitment),
            50,
            Some(ristretto_type.clone()),
            "Returns the delta commitment for the arbitrary range proof."
        );

        // commitment_eq_proof
        env.register_native_function_with_comment(
            "commitment_eq_proof",
            Some(arbitrary_range_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(arbitrary_range_proof_commitment_eq_proof),
            250,
            Some(commitment_equality_proof_type.clone()),
            "Returns the commitment equality proof inside the arbitrary range proof."
        );

        // range_proof
        env.register_native_function_with_comment(
            "range_proof",
            Some(arbitrary_range_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(arbitrary_range_proof_range_proof),
            250,
            Some(range_proof_type.clone()),
            "Returns the range proof inside the arbitrary range proof."
        );

        // verify
        env.register_native_function_with_comment(
            "verify",
            Some(arbitrary_range_proof_type.clone()),
            vec![
                ("source_pubkey", ristretto_type.clone()),
                ("source_ciphertext", ciphertext_type.clone()),
                ("transcript", transcript_type.clone()),
            ],
            FunctionHandler::Sync(arbitrary_range_proof_verify),
            1_600_000,
            Some(Type::Bool),
            "Verifies the arbitrary range proof for the source ciphertext."
        );
    }

    // Ownership Proof
    {
        // OwnershipProof::new
        env.register_static_function_with_comment(
            "new",
            ownership_proof_type.clone(),
            vec![
                ("amount", Type::U64),
                ("commitment", ristretto_type.clone()),
                ("eq_commitment_proof", commitment_equality_proof_type.clone()),
                ("range_proof", range_proof_type.clone()),
            ],
            FunctionHandler::Sync(ownership_proof_new),
            500,
            Some(ownership_proof_type.clone()),
            "Creates an ownership proof wrapper from its components."
        );

        // amount
        env.register_native_function_with_comment(
            "amount",
            Some(ownership_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(ownership_proof_amount),
            1,
            Some(Type::U64),
            "Returns the amount claimed by the ownership proof."
        );

        // commitment
        env.register_native_function_with_comment(
            "commitment",
            Some(ownership_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(ownership_proof_commitment),
            50,
            Some(ristretto_type.clone()),
            "Returns the commitment claimed by the ownership proof."
        );

        // commitment_eq_proof
        env.register_native_function_with_comment(
            "commitment_eq_proof",
            Some(ownership_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(ownership_proof_commitment_eq_proof),
            250,
            Some(commitment_equality_proof_type.clone()),
            "Returns the commitment equality proof inside the ownership proof."
        );

        // range_proof
        env.register_native_function_with_comment(
            "range_proof",
            Some(ownership_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(ownership_proof_range_proof),
            250,
            Some(range_proof_type.clone()),
            "Returns the range proof inside the ownership proof."
        );

        // verify
        env.register_native_function_with_comment(
            "verify",
            Some(ownership_proof_type.clone()),
            vec![
                ("source_pubkey", ristretto_type.clone()),
                ("source_ciphertext", ciphertext_type.clone()),
                ("transcript", transcript_type.clone()),
            ],
            FunctionHandler::Sync(ownership_proof_verify),
            1_600_000,
            Some(Type::Bool),
            "Verifies the ownership proof for the source ciphertext."
        );
    }

    // Balance Proof
    {
        // BalanceProof::new
        env.register_static_function_with_comment(
            "new",
            balance_proof_type.clone(),
            vec![
                ("amount", Type::U64),
                ("commitment_eq_proof", commitment_equality_proof_type.clone()),
            ],
            FunctionHandler::Sync(balance_proof_new),
            250,
            Some(balance_proof_type.clone()),
            "Creates a balance proof wrapper from its components."
        );

        // amount
        env.register_native_function_with_comment(
            "amount",
            Some(balance_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(balance_proof_amount),
            1,
            Some(Type::U64),
            "Returns the amount claimed by the balance proof."
        );

        // eq_commitment_proof
        env.register_native_function_with_comment(
            "commitment_eq_proof",
            Some(balance_proof_type.clone()),
            vec![],
            FunctionHandler::Sync(balance_proof_commitment_eq_proof),
            250,
            Some(commitment_equality_proof_type.clone()),
            "Returns the commitment equality proof inside the balance proof."
        );

        // verify
        env.register_native_function_with_comment(
            "verify",
            Some(balance_proof_type.clone()),
            vec![
                ("source_pubkey", ristretto_type.clone()),
                ("source_ciphertext", ciphertext_type.clone()),
                ("transcript", transcript_type.clone()),
            ],
            FunctionHandler::Sync(balance_proof_verify),
            1_600_000,
            Some(Type::Bool),
            "Verifies the balance proof for the source ciphertext."
        );
    }

    // Module Opaque
    {
        env.register_static_function_with_comment(
            "new",
            contract_type.clone(),
            vec![
                ("contract", hash_type.clone()),
            ],
            FunctionHandler::Async(async_handler!(contract_new::<P>)),
            1500,
            Some(Type::Optional(Box::new(contract_type.clone()))),
            "Loads a contract handle by hash, if available."
        );

        // Call a module chunk from this contract
        // This will check for the permission given by the user if any
        // Module#call is calling on behalf of the current transaction
        env.register_native_function_with_comment(
            "call",
            Some(contract_type.clone()),
            vec![
                ("chunk_id", Type::U16),
                ("args", Type::Array(Box::new(Type::Any))),
                // Funds we want to transfer to this contract
                // Those funds are taken from the current contract
                ("deposits", Type::Map(Box::new(hash_type.clone()), Box::new(Type::U64))),
            ],
            FunctionHandler::Async(async_handler!(contract_call::<P>)),
            750,
            Some(Type::Voidable(Box::new(Type::Any))),
            "Calls a callable chunk on this contract and optionally deposits funds."
        );

        // Similar to invoke, but allows to delegate the call to another contract
        // So it will act as your own contract
        env.register_native_function_with_comment(
            "delegate",
            Some(contract_type.clone()),
            vec![
                ("chunk_id", Type::U16),
                ("args", Type::Array(Box::new(Type::Any))),
            ],
            FunctionHandler::Async(async_handler!(contract_delegate)),
            100,
            Some(Type::Voidable(Box::new(Type::Any))),
            "Delegates a call to this contract so it runs as the caller's contract."
        );

        // Get the contract hash
        env.register_native_function_with_comment(
            "get_hash",
            Some(contract_type.clone()),
            vec![],
            FunctionHandler::Sync(contract_get_hash),
            5,
            Some(hash_type.clone()),
            "Returns this contract hash."
        );
    }

    // Scheduled Execution
    {
        // ScheduledExecution::new_at_topoheight
        env.register_static_function_with_comment(
            "new_at_topoheight",
            scheduled_execution_type.clone(),
            vec![
                ("callback", Type::Function(FnType::new(None, false, vec![Type::Array(Box::new(Type::Any))], Some(Type::U64)))),
                ("args", Type::Array(Box::new(Type::Any))),
                ("max_gas", Type::U64),
                ("use_contract_balance", Type::Bool),
                ("topoheight", Type::U64),
            ],
            FunctionHandler::Async(async_handler!(scheduled_execution_new_at_topoheight::<P>)),
            // Contains the hash computation cost
            3500,
            Some(Type::Optional(Box::new(scheduled_execution_type.clone()))),
            "Schedules a callback execution at a specific topoheight."
        );

        // ScheduledExecution::new_at_block_end
        // Same as above, but directly executed at the end of this block
        env.register_static_function_with_comment(
            "new_at_block_end",
            scheduled_execution_type.clone(),
            vec![
                ("callback", Type::Function(FnType::new(None, false, vec![Type::Array(Box::new(Type::Any))], Some(Type::U64)))),
                ("args", Type::Array(Box::new(Type::Any))),
                ("max_gas", Type::U64),
                ("use_contract_balance", Type::Bool),
            ],
            FunctionHandler::Async(async_handler!(scheduled_execution_new_at_block_end::<P>)),
            // Contains the hash computation cost
            3500,
            Some(Type::Optional(Box::new(scheduled_execution_type.clone()))),
            "Schedules a callback execution at the end of the current block."
        );

        // Get the hash generated when scheduling this execution
        env.register_native_function_with_comment(
            "get_hash",
            Some(scheduled_execution_type.clone()),
            vec![],
            FunctionHandler::Sync(scheduled_execution_get_hash),
            5,
            Some(hash_type.clone()),
            "Returns the hash generated for the scheduled execution."
        );

        // Get the topoheight at which this execution is scheduled
        env.register_native_function_with_comment(
            "get_topoheight",
            Some(scheduled_execution_type.clone()),
            vec![],
            FunctionHandler::Sync(scheduled_execution_get_topoheight),
            5,
            Some(Type::Optional(Box::new(Type::U64))),
            "Returns the topoheight at which the execution is scheduled, if any."
        );

        // Get the max gas allowed for this scheduled execution
        env.register_native_function_with_comment(
            "get_max_gas",
            Some(scheduled_execution_type.clone()),
            vec![],
            FunctionHandler::Sync(scheduled_execution_get_max_gas),
            5,
            Some(Type::U64),
            "Returns the maximum gas allowed for the scheduled execution."
        );

        // Get a currently pending scheduled execution registered in current block
        // If none found, returns None
        env.register_static_function_with_comment(
            "get_pending",
            scheduled_execution_type.clone(),
            vec![("topoheight", Type::Optional(Box::new(Type::U64)))],
            FunctionHandler::Sync(scheduled_execution_get_pending),
            1500,
            Some(Type::Optional(Box::new(scheduled_execution_type.clone()))),
            "Returns a pending scheduled execution for the topoheight, if any."
        );

        // Increase max gas allowed for this scheduled execution
        // It can only work if a scheduled execution created/pending in current block
        // If use_contract_balance is set to true, it will use the contract balance to pay for the gas increase
        // Otherwise, it will use the transaction gas allowance
        env.register_native_function_with_comment(
            "increase_max_gas",
            Some(scheduled_execution_type.clone()),
            vec![
                ("amount", Type::U64),
                ("use_contract_balance", Type::Bool)
            ],
            FunctionHandler::Async(async_handler!(scheduled_execution_increase_max_gas::<P>)),
            500,
            Some(Type::Bool),
            "Increases the max gas for a pending scheduled execution."
        );
    }

    // Misc
    {
        // Get the current contract hash
        env.register_native_function_with_comment(
            "get_contract_hash",
            None,
            vec![],
            FunctionHandler::Sync(get_contract_hash),
            5,
            Some(hash_type.clone()),
            "Returns the hash of the currently executing contract."
        );

        // Get the initial contract hash used as an entry point
        env.register_native_function_with_comment(
            "get_contract_entry",
            None,
            vec![],
            FunctionHandler::Sync(get_contract_entry),
            5,
            Some(hash_type.clone()),
            "Returns the initial contract hash used as the entry point."
        );

        // Get the contract caller if any
        // Useful to know if it was called by another contract
        env.register_native_function_with_comment(
            "get_contract_caller",
            None,
            vec![],
            FunctionHandler::Sync(get_contract_caller),
            5,
            Some(Type::Optional(Box::new(hash_type.clone()))),
            "Returns the calling contract hash, if any."
        );

        // Retrieve the deposit for the given asset
        env.register_native_function_with_comment(
            "get_deposit_for_asset",
            None,
            vec![("asset", hash_type.clone())],
            FunctionHandler::Sync(get_deposit_for_asset),
            5,
            Some(Type::Optional(Box::new(Type::U64))),
            "Returns the public deposit amount for the given asset, if any."
        );
        // Retrieve the deposit for the given asset
        env.register_native_function_with_comment(
            "get_deposits",
            None,
            vec![],
            FunctionHandler::Sync(get_deposits),
            15,
            Some(Type::Map(Box::new(hash_type.clone()), Box::new(Type::U64))),
            "Returns all public deposits received by this invocation."
        );

        // Retrieve the balance for the given asset
        env.register_native_function_with_comment(
            "get_balance_for_asset",
            None,
            vec![("asset", hash_type.clone())],
            FunctionHandler::Async(async_handler!(get_balance_for_asset::<P>)),
            25,
            Some(Type::Optional(Box::new(Type::U64))),
            "Returns the current contract balance for the given asset, if any."
        );

        // Retrieve the balance for the given asset of a contract
        env.register_native_function_with_comment(
            "get_contract_balance_for_asset",
            None,
            vec![
                ("contract", hash_type.clone()),
                ("asset", hash_type.clone())
            ],
            FunctionHandler::Async(async_handler!(get_contract_balance_for_asset::<P>)),
            250,
            Some(Type::Optional(Box::new(Type::U64))),
            "Returns another contract's balance for the given asset, if any."
        );

        // Transfer asset to an account
        env.register_native_function_with_comment(
            "transfer",
            None,
            vec![
                ("destination", address_type.clone()),
                ("amount", Type::U64),
                ("asset", hash_type.clone()),
            ],
            FunctionHandler::Async(async_handler!(transfer::<P>)),
            500,
            Some(Type::Bool),
            "Transfers an asset from the current contract to an account."
        );

        // Transfer asset to a contract
        env.register_native_function_with_comment(
            "transfer_contract",
            None,
            vec![
                ("contract", hash_type.clone()),
                ("amount", Type::U64),
                ("asset", hash_type.clone()),
            ],
            FunctionHandler::Async(async_handler!(transfer_contract::<P>)),
            250,
            Some(Type::Bool),
            "Transfers an asset from the current contract to another contract."
        );

        // Burn an asset
        env.register_native_function_with_comment(
            "burn",
            None,
            vec![
                ("amount", Type::U64),
                ("asset", hash_type.clone()),
            ],
            FunctionHandler::Async(async_handler!(burn::<P>)),
            500,
            Some(Type::Bool),
            "Burns an asset amount from the current contract balance."
        );

        // Generate a RPC event from contract
        // this is useful for applications that want to be 
        // dynamic and raise events on a specific action
        env.register_native_function_with_comment(
            "fire_rpc_event",
            None,
            vec![
                ("id", Type::U64),
                ("data", Type::Any)
            ],
            FunctionHandler::Sync(rpc_event_fn),
            250,
            None,
            "Records an RPC event for off-chain applications."
        );

        // Retrieve the ciphertext and the topoheight at which it got fetched
        env.register_native_function_with_comment(
            "get_account_balance_for_asset",
            None,
            vec![
                ("address", address_type.clone()),
                ("asset", hash_type.clone())
            ],
            FunctionHandler::Async(async_handler!(get_account_balance_for_asset::<P>)),
            1000,
            Some(Type::Optional(Box::new(Type::Tuples(vec![Type::U64, ciphertext_type.clone()])))),
            "Returns an account balance ciphertext and fetched topoheight for the asset, if any."
        );

        // Get the current gas usage
        env.register_native_function_with_comment(
            "get_gas_usage",
            None,
            vec![],
            FunctionHandler::Sync(get_gas_usage),
            1,
            Some(Type::U64),
            "Returns the current gas used by the execution."
        );

        // Current gas limit allowed by the VM
        env.register_native_function_with_comment(
            "get_gas_limit",
            None,
            vec![],
            FunctionHandler::Sync(get_gas_limit),
            1,
            Some(Type::U64),
            "Returns the current VM gas limit."
        );

        // Increase the gas limit for the caller using contract funds
        // It is limited to `MAX_GAS_USAGE_PER_TX` in total
        env.register_native_function_with_comment(
            "increase_gas_limit",
            None,
            vec![("amount", Type::U64)],
            FunctionHandler::Async(async_handler!(increase_gas_limit::<P>)),
            250,
            Some(Type::Bool),
            "Increases the VM gas limit using current contract funds."
        );

        // Current block topoheight in which we are executing this contract
        env.register_native_function_with_comment(
            "get_current_topoheight",
            None,
            vec![],
            FunctionHandler::Sync(get_current_topoheight),
            1,
            Some(Type::U64),
            "Returns the current execution topoheight."
        );

        // Get the caller address if any
        // This may returns null if no address is available
        env.register_native_function_with_comment(
            "get_caller",
            None,
            vec![],
            FunctionHandler::Sync(get_caller),
            20,
            Some(Type::Optional(Box::new(address_type.clone()))),
            "Returns the caller account address, if any."
        );

        // Get the current cost per asset created
        // returns in atomic units `COST_PER_ASSET`
        env.register_native_function_with_comment(
            "get_cost_per_asset",
            None,
            vec![],
            FunctionHandler::Sync(get_cost_per_asset),
            1,
            Some(Type::U64),
            "Returns the asset creation cost in atomic units."
        );

        // Get the current cost per scheduled exection
        // returns in atomic units `COST_PER_DELAYED_EXECUTION`
        env.register_native_function_with_comment(
            "get_cost_per_scheduled_execution",
            None,
            vec![],
            FunctionHandler::Sync(get_cost_per_scheduled_execution),
            1,
            Some(Type::U64),
            "Returns the scheduled execution cost in atomic units."
        );

        // Is contract callable
        env.register_native_function_with_comment(
            "is_contract_callable",
            None,
            vec![
                ("contract", hash_type.clone()),
                ("chunk_id", Type::U16)
            ],
            FunctionHandler::Sync(is_contract_callable),
            75,
            Some(Type::Bool),
            "Returns whether a contract chunk is callable under current permissions."
        );

        // XOR 2 hashes together
        env.register_native_function_with_comment(
            "xor_hashes",
            None,
            vec![
                ("hash1", hash_type.clone()),
                ("hash2", hash_type.clone())
            ],
            FunctionHandler::Sync(xor_hashes),
            50,
            Some(hash_type.clone()),
            "Returns the bytewise XOR of two hashes."
        );
    }

    // BTree Storage
    {
        env.register_static_function_with_comment(
            "new",
            btree_store_type.clone(),
            vec![("namespace", Type::Bytes)],
            FunctionHandler::Sync(btree_store_new),
            5,
            Some(btree_store_type.clone()),
            "Creates a BTree store for the given namespace."
        );
        env.register_native_function_with_comment(
            "insert",
            Some(btree_store_type.clone()),
            vec![("key", Type::Bytes), ("value", Type::Any)],
            FunctionHandler::Async(async_handler!(btree_store_insert::<P>)),
            100,
            None,
            "Inserts a key and value into the BTree store."
        );

        // NOTE: "get" will only work deterministically if there are only unique keys.
        // For duplicate keys, you must use a cursor.
        env.register_native_function_with_comment(
            "get",
            Some(btree_store_type.clone()),
            vec![("key", Type::Bytes)],
            FunctionHandler::Async(async_handler!(btree_store_get::<P>)),
            75,
            Some(Type::Optional(Box::new(Type::Any))),
            "Returns the value for a unique key in the BTree store, if any."
        );

        // NOTE: "delete" will only work deterministically if there are only unique keys.
        // For duplicate keys, you must use a cursor.
        env.register_native_function_with_comment(
            "delete",
            Some(btree_store_type.clone()),
            vec![("key", Type::Bytes)],
            FunctionHandler::Async(async_handler!(btree_store_delete::<P>)),
            75,
            Some(Type::Bool),
            "Deletes a unique key from the BTree store."
        );
        env.register_native_function_with_comment(
            "seek",
            Some(btree_store_type.clone()),
            vec![
                ("key", Type::Bytes),
                ("bias", btree_seek_bias_type.clone()),
                ("ascending", Type::Bool),
            ],
            FunctionHandler::Async(async_handler!(btree_store_seek::<P>)),
            100,
            Some(Type::Tuples(vec![
                btree_cursor_type.clone(),
                Type::Optional(Box::new(entry_type.clone())),
            ])),
            "Creates a cursor at the requested key using the seek bias and direction."
        );
        env.register_native_function_with_comment(
            "len",
            Some(btree_store_type.clone()),
            vec![],
            FunctionHandler::Async(async_handler!(btree_store_len::<P>)),
            25,
            Some(Type::U64),
            "Returns the number of entries in the BTree store."
        );
    }

    // BTree Cursor
    {
        env.register_native_function_with_comment(
            "next",
            Some(btree_cursor_type.clone()),
            vec![],
            FunctionHandler::Async(async_handler!(btree_cursor_next::<P>)),
            15,
            Some(Type::Optional(Box::new(entry_type.clone()))),
            "Returns the next cursor entry, if any."
        );
        env.register_native_function_with_comment(
            "delete",
            Some(btree_cursor_type.clone()),
            vec![],
            FunctionHandler::Async(async_handler!(btree_cursor_delete::<P>)),
            20,
            Some(Type::Bool),
            "Deletes the current cursor entry."
        );
    }

    if version >= ContractVersion::V1 {
        // Transfer asset to an account
        env.register_native_function_with_comment(
            "transfer_payload",
            None,
            vec![
                ("destination", address_type.clone()),
                ("amount", Type::U64),
                ("asset", hash_type.clone()),
                ("payload", Type::Any),
            ],
            FunctionHandler::Async(async_handler!(transfer_payload::<P>)),
            550,
            Some(Type::Bool),
            "Transfers an asset to an account with an attached payload."
        );

        // Asset::get_decimals
        env.register_native_function_with_comment(
            "get_decimals",
            Some(asset_type.clone()),
            vec![],
            FunctionHandler::Sync(asset_get_decimals),
            3,
            Some(Type::U8),
            "Returns the decimal precision for the asset."
        );

        // Send an event that can be captured by others contracts which are listening to it
        env.register_native_function_with_comment(
            "emit_event",
            None,
            vec![
                // event_id
                ("id", Type::U64),
                // parameters to give with this event
                ("args", Type::Array(Box::new(Type::Any))),
            ],
            FunctionHandler::Sync(emit_event_fn),
            1000,
            None,
            "Emits a contract event with arguments for listeners."
        );

        env.register_native_function_with_comment(
            "listen_event",
            Some(contract_type.clone()),
            vec![
                // event_id
                ("id", Type::U64),
                // chunk id to call when event is captured
                ("callback", Type::Function(FnType::new(None, false, vec![Type::Array(Box::new(Type::Any))], Some(Type::U64)))),
                // max gas to use when calling the event listener
                ("max_gas", Type::U64),
            ],
            FunctionHandler::Async(async_handler!(listen_event_fn::<P>)),
            5000,
            Some(Type::Bool),
            "Registers the current contract as a listener for this contract's event."
        );

        // returns the XELIS asset hash
        env.register_native_function_with_comment(
            "get_xelis_asset",
            None,
            vec![],
            FunctionHandler::Sync(get_xelis_asset),
            1,
            Some(hash_type.clone()),
            "Returns the native XELIS asset hash."
        );

        // Ciphertext improvements

        // Ciphertext::new(commitment, handle)
        env.register_static_function_with_comment(
            "new",
            ciphertext_type.clone(),
            vec![
                ("commitment", ristretto_type.clone()),
                ("handle", ristretto_type.clone()),
            ],
            FunctionHandler::Sync(ciphertext_new),
            50,
            Some(ciphertext_type.clone()),
            "Creates a ciphertext from commitment and handle points."
        );

        // Ciphertext#add_ct(other)
        env.register_native_function_with_comment(
            "add_ct",
            Some(ciphertext_type.clone()),
            vec![
                ("other", ciphertext_type.clone()),
            ],
            FunctionHandler::Sync(ciphertext_add_ct),
            9000,
            None,
            "Adds another ciphertext to this ciphertext in place."
        );
        // Ciphertext#sub_ct(other)
        env.register_native_function_with_comment(
            "sub_ct",
            Some(ciphertext_type.clone()),
            vec![
                ("other", ciphertext_type.clone()),
            ],
            FunctionHandler::Sync(ciphertext_sub_ct),
            9000,
            None,
            "Subtracts another ciphertext from this ciphertext in place."
        );
        // Ciphertext#add_scalar(scalar)
        env.register_native_function_with_comment(
            "add_scalar",
            Some(ciphertext_type.clone()),
            vec![
                ("scalar", scalar_type.clone()),
            ],
            FunctionHandler::Sync(ciphertext_add_scalar),
            14_000,
            None,
            "Adds a scalar to this ciphertext in place."
        );
        // Ciphertext#sub_scalar(scalar)
        env.register_native_function_with_comment(
            "sub_scalar",
            Some(ciphertext_type.clone()),
            vec![
                ("scalar", scalar_type.clone()),
            ],
            FunctionHandler::Sync(ciphertext_sub_scalar),
            14_000,
            None,
            "Subtracts a scalar from this ciphertext in place."
        );

        // Scalar improvements

        // Scalar::hash_from_bytes(bytes)
        env.register_static_function_with_comment(
            "hash_from_bytes",
            scalar_type.clone(),
            vec![
                ("bytes", Type::Bytes)
            ],
            FunctionHandler::Sync(scalar_hash_from_bytes),
            10000,
            Some(scalar_type.clone()),
            "Hashes bytes into a scalar."
        );
    }

    env
}

#[inline]
pub fn provider_from_context<'a, 'ty, 'r, P: ContractProvider<'ty>>(context: &'a VMContext<'ty, 'r>) -> Result<&'a P, anyhow::Error> {
    context.get::<P>().context("Provider not initialized")
}

#[inline]
pub fn state_from_context<'a, 'ty, 'r>(context: &'a mut VMContext<'ty, 'r>) -> Result<&'a mut ChainState<'ty>, anyhow::Error> {
    context.get_mut::<ChainState>()
        .context("Chain state not initialized")
}

pub fn from_context<'a, 'ty, 'r, P: ContractProvider<'ty>>(context: &'a mut VMContext<'ty, 'r>) -> Result<(&'a P, &'a mut ChainState<'ty>), anyhow::Error> {
    let mut datas = context.get_disjoint_mut([&P::id(), &TypeId::of::<ChainState>()]);

    let provider: &P = datas[0]
        .take()
        .context("Contract Environment is not initialized")?
        .downcast_ref::<P>()
        .context("Contract Environment is not initialized correctly")?;

    let state: &mut ChainState = datas[1]
        .take()
        .context("Chain state is not initialized")?
        .downcast_mut()
        .context("Chain state is not initialized correctly")?;

    Ok((provider, state))
}

// Function helper to get the balance for the given asset
// This will first check in our current changes, then in the previous execution cache
pub async fn get_balance_from_cache<'a, 'b: 'a, 'ty, P: ContractProvider<'ty>>(provider: &P, state: &'a mut ChainState<'b>, contract: Hash, asset: Hash) -> Result<&'a mut Option<(VersionedState, u64)>, anyhow::Error> {
    Ok(match get_cache_for_contract(&mut state.changes.caches, state.global_caches, contract.clone(), state.cache_clone_refs).balances.entry(asset.clone()) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            let v = get_balance_from_provider(provider, state.topoheight, &contract, &asset).await?;
            entry.insert(v)
        }
    })
}

// Function helper to get the mutable balance for the given asset
pub async fn get_mut_balance_for_contract<'a, 'b: 'a, 'ty, P: ContractProvider<'ty>>(provider: &P, state: &'a mut ChainState<'b>, contract: Hash, asset: Hash) -> Result<&'a mut (VersionedState, u64), anyhow::Error> {
    Ok(match get_cache_for_contract(&mut state.changes.caches, state.global_caches, contract.clone(), state.cache_clone_refs).balances.entry(asset.clone()) {
        Entry::Occupied(entry) => entry.into_mut()
            .get_or_insert((VersionedState::New, 0)),
        Entry::Vacant(entry) => {
            let ptr = entry.insert(None);
            let v = get_balance_from_provider(provider, state.topoheight, &contract, &asset).await?
                .unwrap_or_else(|| (VersionedState::New, 0));

            ptr.insert(v)
        }
    })
}

// Get the cache for the given contract, if it doesn't exist, it will be created and initialized with the global cache if exists
pub fn get_cache_for_contract<'a>(caches: &'a mut HashMap<Hash, ContractCache>, global_caches: &'a HashMap<Hash, ContractCache>, contract: Hash, clone_refs: bool) -> &'a mut ContractCache {
    match caches.entry(contract) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            let cache = global_caches.get(entry.key())
                .map(|c| c.clone_with(clone_refs))
                .unwrap_or_default();

            entry.insert(cache)
        }
    }
}

pub fn get_optional_cache_for_contract<'a>(caches: &'a HashMap<Hash, ContractCache>, global_caches: &'a HashMap<Hash, ContractCache>, contract: &Hash) -> Option<&'a ContractCache> {
    match caches.get(contract) {
        Some(entry) => Some(entry),
        None => global_caches.get(contract)
    }
}

pub async fn get_balance_from_provider<'ty, P: ContractProvider<'ty>>(provider: &P, topoheight: TopoHeight, contract: &Hash, asset: &Hash) -> Result<Option<(VersionedState, u64)>, anyhow::Error> {
    let balance = provider.get_contract_balance_for_asset(contract, asset, topoheight).await?;
    Ok(balance.map(|(topoheight, balance)| (VersionedState::FetchedAt(topoheight), balance)))
}

pub async fn get_optional_asset_from_cache<'a, 'b: 'a, 'ty, P: ContractProvider<'ty>>(provider: &P, state: &'a mut ChainState<'b>, asset: Hash) -> Result<&'a mut Option<AssetChanges>, anyhow::Error> {
    Ok(match state.changes.assets.entry(asset.clone()) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            let v = get_asset_from_provider(provider, state.topoheight, &asset).await?;
            entry.insert(v)
        }
    })
}

pub fn get_asset_changes_for_hash<'a>(state: &'a ChainState, hash: &'a Hash) -> Result<&'a AssetChanges, anyhow::Error> {
    state.changes.assets.get(hash)
        .map(|v| v.as_ref())
        .flatten()
        .context("Asset not found in cache")
}

pub fn get_asset_changes_for_hash_mut<'a>(state: &'a mut ChainState, hash: &'a Hash) -> Result<&'a mut AssetChanges, anyhow::Error> {
    state.changes.assets.get_mut(hash)
        .map(|v| v.as_mut())
        .flatten()
        .context("Asset not found in cache")
}

pub async fn get_asset_from_cache<'a, 'b, 'ty, P: ContractProvider<'ty>>(provider: &P, state: &'a mut ChainState<'b>, asset: Hash) -> Result<&'a mut AssetChanges, anyhow::Error> {
    get_optional_asset_from_cache(provider, state, asset).await?
        .as_mut()
        .context("Asset not found for provided hash")
}

// Record a burn in the asset supply
pub async fn record_burned_asset<'a, 'b, 'ty, P: ContractProvider<'ty>>(provider: &P, state: &'a mut ChainState<'b>, contract: Hash, asset: Hash, amount: u64) -> Result<(), anyhow::Error> {
    let changes = get_asset_from_cache(provider, state, asset.clone()).await?;

    let new_supply = changes.circulating_supply.1
        .checked_sub(amount)
        .context("Overflow while burning supply")?;

    changes.circulating_supply.1 = new_supply;
    changes.circulating_supply.0.mark_updated();

    // Add the output
    state.logs.push(ContractLog::Burn { contract, asset, amount });

    Ok(())
}

// Check if the contract has enough balance for the given asset and amount
pub async fn has_enough_balance_for_contract<'ty, P: ContractProvider<'ty>>(provider: &P, state: &mut ChainState<'_>, contract: Hash, asset: Hash, amount: u64) -> Result<bool, anyhow::Error> {
    let balance_opt = get_balance_from_cache(provider, state, contract, asset).await?;

    Ok(match balance_opt {
        Some((_, balance)) => *balance >= amount,
        None => false
    })
}

// Record a balance charge for the given contract and asset
pub async fn record_balance_charge<'a, 'b, 'ty, P: ContractProvider<'ty>>(provider: &P, state: &'a mut ChainState<'b>, contract: Hash, asset: Hash, amount: u64) -> Result<(), anyhow::Error> {
    let (state, balance) = get_mut_balance_for_contract(provider, state, contract, asset).await?;

    state.mark_updated();
    *balance = balance.checked_sub(amount)
        .context("Underflow while charging balance")?;

    Ok(())
}

// Record a balance credit for the given contract and asset
pub async fn record_balance_credit<'a, 'b, 'ty, P: ContractProvider<'ty>>(provider: &P, state: &'a mut ChainState<'b>, contract: Hash, asset: Hash, amount: u64) -> Result<(), anyhow::Error> {
    let (state, balance) = get_mut_balance_for_contract(provider, state, contract, asset).await?;

    state.mark_updated();
    *balance = balance.checked_add(amount)
        .context("Overflow while crediting balance")?;

    Ok(())
}

// Record an account balance credit for the given address and asset
pub async fn record_account_balance_credit<'a, 'b>(
    state: &'a mut ChainState<'b>,
    from_contract: Hash,
    address: Address,
    asset: Hash,
    amount: u64,
    payload: Option<ValueCell>,
) -> Result<(), anyhow::Error> {
    let key = address.to_public_key();

    // Aggregated transfers for this address
    // this is easier to apply at the end of the execution
    match state.changes.tracker.aggregated_transfers.entry(key.clone())
        .or_insert_with(HashMap::new)
        .entry(asset.clone())
    {
        Entry::Occupied(mut entry) => {
            *entry.get_mut() = entry.get().checked_add(amount)
                .context("Overflow while aggregating contract transfer")?;
        },
        Entry::Vacant(entry) => {
            entry.insert(amount);
        }
    }

    // The caller hash (either scheduled execution or TX contract call)
    let caller = state.caller.get_hash()
        .as_ref()
        .clone();

    // Detailed transfers from contract to address for better outputs tracking
    match state.changes.tracker.contracts_transfers.entry((caller, from_contract.clone()))
        .or_insert_with(HashMap::new)
        .entry(key.clone())
        .or_insert_with(HashMap::new)
        .entry(asset.clone())
    {
        Entry::Occupied(mut entry) => {
            *entry.get_mut() = entry.get().checked_add(amount)
                .context("Overflow while aggregating contract output")?;
        },
        Entry::Vacant(entry) => {
            entry.insert(amount);
        }
    }

    // Add the output
    state.logs.push(match payload {
        Some(payload) => ContractLog::TransferPayload { contract: from_contract, destination: key, amount, asset, payload },
        None => ContractLog::Transfer { contract: from_contract, destination: key, amount, asset },
    });

    Ok(())
}

// Take from the available gas fee and increase the state gas fee allowance
// this will be reduced from the final used gas to prevent double charging
pub fn record_gas_allowance<'ty, 'r>(context: &mut VMContext<'ty, 'r>, amount: u64) -> Result<(), anyhow::Error> {
    context.increase_gas_usage(amount)?;

    let state = state_from_context(context)?;
    state.gas_fee_allowance = state.gas_fee_allowance.checked_add(amount)
        .context("Overflow while increasing gas allowance")?;

    Ok(())
}

pub async fn get_asset_from_provider<'ty, P: ContractProvider<'ty>>(provider: &P, topoheight: TopoHeight, asset: &Hash) -> Result<Option<AssetChanges>, anyhow::Error> {
    match provider.load_asset_data(asset, topoheight).await? {
        Some((topo, data)) => {
            let (supply_topo, supply) = provider.load_asset_circulating_supply(asset, topoheight).await?;

            Ok(Some(AssetChanges {
                data: (VersionedState::FetchedAt(topo), data),
                circulating_supply: (VersionedState::FetchedAt(supply_topo), supply)
            }))
        },
        None => Ok(None)
    }
}

fn rpc_event_fn(_: FnInstance, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let data = params.remove(1);
    let id = params.remove(0)
        .as_u64()?;

    let constant = data.into_owned();

    let size = constant.size();
    let cost = FEE_PER_BYTE_OF_EVENT_DATA * size as u64;
    context.increase_gas_usage(cost)?;

    // Ensure that the event is actually serializable
    if !constant.is_json_serializable() {
        return Err(EnvironmentError::Static("Event not serializable"))
    }

    let state = state_from_context(context)?;
    let entry = get_cache_for_contract(&mut state.changes.caches, state.global_caches, metadata.metadata.contract_executor.clone(), state.cache_clone_refs)
        .events.entry(id)
        .or_insert_with(Vec::new);

    entry.push(constant);

    Ok(SysCallResult::None)
}

fn emit_event_fn(_: FnInstance, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let args = params.remove(1)
        .into_owned()
        .to_vec()?
        .into_iter()
        .map(|v| v.into_owned())
        .collect();

    let id = params.remove(0)
        .as_u64()?;

    let state = state_from_context(context)?;

    state.logs.push(ContractLog::Event {
        contract: metadata.metadata.contract_executor.clone(),
        event_id: id,
    });

    state.changes.events.push(CallbackEvent {
        contract: metadata.metadata.contract_executor.clone(),
        event_id: id,
        params: args,
    });

    Ok(SysCallResult::None)
}

// Listen to an event from a contract
// Once triggered, it will call the given chunk_id with the event parameters
// with allocated gas and will be removed from the listeners after being called
async fn listen_event_fn<'a, 'ty, 'r, P: ContractProvider<'ty>>(zelf: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let contract = zelf?
        .as_opaque_type::<OpaqueContract>()?
        .hash
        .clone();

    let max_gas = params.remove(2)
        .as_u64()?;

    if max_gas > MAX_GAS_USAGE_PER_TX {
        return Err(EnvironmentError::Static("max_gas exceeds allowed limit"))
    }

    let chunk_id = params.remove(1)
        .as_u16()?;

    // Check if the chunk_id is valid and callable
    if !metadata.module.is_callable_chunk(chunk_id as _) {
        return Ok(SysCallResult::Return(Primitive::Null.into()));
    }

    let event_id = params.remove(0)
        .as_u64()?;

    let (provider, state) = from_context::<P>(context)?;
    // check from storage that we're not already registered
    if provider.has_contract_callback_for_event(
        &contract,
        event_id,
        &metadata.metadata.contract_executor,
        state.topoheight,
    ).await? {
        return Ok(Primitive::Boolean(false).into());
    }

    let cache = get_cache_for_contract(&mut state.changes.caches, state.global_caches, metadata.metadata.contract_executor.clone(), state.cache_clone_refs);

    // Event is already registered in our cache
    if !cache.events_listeners.insert((contract.clone(), event_id)) {
        return Ok(Primitive::Boolean(false).into());
    }

    let listeners = state.changes.events_listeners.entry((contract.clone(), event_id))
        .or_insert_with(Default::default);

    let callback = EventCallbackRegistration { chunk_id, max_gas };
    listeners.push((metadata.metadata.contract_executor.clone(), callback));

    record_gas_allowance(context, max_gas)?;

    Ok(Primitive::Boolean(true).into())
}

fn get_xelis_asset(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(XELIS_ASSET.clone())).into()))
}

fn println_fn(_: FnInstance, params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;
    if state.debug_mode {
        info!("[{}#{}]: {}", state.entry_contract, metadata.metadata.contract_executor, params[0].as_ref());
    }

    Ok(SysCallResult::None)
}

fn debug_fn(_: FnInstance, params: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;
    if state.debug_mode {
        debug!("{:?}", params[0].as_ref());
    }

    Ok(SysCallResult::None)
}

fn get_contract_hash(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(metadata.metadata.contract_executor.clone())).into()))
}

fn get_contract_entry(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(state.entry_contract.as_ref().clone())).into()))
}

fn get_contract_caller(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    // For inter-contract calls (contract A calls contract B), metadata carries the direct caller.
    if let Some(caller) = metadata.metadata.contract_caller.as_ref() {
        return Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(caller.clone())).into()));
    }

    // For event callbacks, the emitting contract acts as the logical caller.
    // We must NOT use ContractCaller::get_hash() here because for TX-originated callbacks
    // that would return the TX hash rather than the contract that emitted the event.
    let state = state_from_context(context)?;
    if let ContractCaller::EventCallback(_, emitting_contract) = &state.caller {
        return Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(emitting_contract.as_ref().clone())).into()));
    }

    Ok(SysCallResult::Return(ValueCell::default().into()))
}

fn get_deposit_for_asset(_: FnInstance, params: FnParams, metadata: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let param = params[0].as_ref();
    let asset: &Hash = param
        .as_opaque_type()
        .context("invalid asset")?;

    let value = match metadata.metadata.deposits.get(asset) {
        Some(ContractDeposit::Public(amount)) => Primitive::U64(*amount).into(),
        _ => ValueCell::default()
    };

    Ok(SysCallResult::Return(value.into()))
}

fn get_deposits(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let mut map = IndexMap::new();

    for (asset, deposit) in metadata.metadata.deposits.iter() {
        if let ContractDeposit::Public(amount) = deposit {
            let key = Primitive::Opaque(asset.clone().into()).into();
            let value = Primitive::U64(*amount).into();
            map.insert(key, value);
        }
    }

    Ok(SysCallResult::Return(ValueCell::Map(Box::new(map)).into()))
}

// Get the current contract balance for the given asset
async fn get_balance_for_asset<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    let asset: Hash = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let balance: ValueCell = get_balance_from_cache(provider, state, metadata.metadata.contract_executor.clone(), asset).await?
        .map(|(_, v)| Primitive::U64(v).into())
        .unwrap_or_default();

    Ok(SysCallResult::Return(balance.into()))
}

// Get the balance for the given contract and asset
async fn get_contract_balance_for_asset<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    let asset: Hash = params.remove(1)
        .into_owned()
        .into_opaque_type()?;

    let contract: Hash = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let balance: ValueCell = get_balance_from_cache(provider, state, contract, asset).await?
        .map(|(_, v)| Primitive::U64(v).into())
        .unwrap_or_default();

    Ok(SysCallResult::Return(balance.into()))
}

async fn transfer_internal<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>, payload: bool) -> Result<bool, EnvironmentError> {
    debug!("Transfer called {:?}", params);

    let payload = if payload {
        let payload = params.remove(3)
            .into_owned();

        if !payload.is_json_serializable() || !payload.is_serializable() {
            debug!("Payload is not serializable");
            return Ok(false);
        }

        let bytes = data_size_in_bytes(&payload);
        if bytes > CONTRACT_MAX_PAYLOAD_SIZE {
            debug!("Payload size {} exceeds maximum allowed {}", bytes, CONTRACT_MAX_PAYLOAD_SIZE);
            return Ok(false);
        }

        context.increase_gas_usage(CONTRACT_PAYLOAD_FEE_PER_BYTE * bytes as u64)?;

        Some(payload)
    } else {
        None
    };

    let asset: Hash = params.remove(2)
        .into_owned()
        .into_opaque_type()?;

    let amount = params.remove(1)
        .into_owned()
        .to_u64()?;

    let destination: Address = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    if !destination.is_normal() {
        return Ok(false);
    }

    {
        let (provider, chain_state) = from_context::<P>(context)?;
        // verify that the address is well registered, otherwise: pay extra fees
        if !provider.account_exists(destination.get_public_key(), chain_state.topoheight).await? {
            context.increase_gas_usage(FEE_PER_ACCOUNT_CREATION)?;
        }
    }

    let (provider, state) = from_context::<P>(context)?;
    if destination.is_mainnet() != state.mainnet {
        return Ok(false);
    }

    if amount == 0 {
        return Ok(false);
    }

    // We have to check if the contract has enough balance to transfer
    if !has_enough_balance_for_contract(provider, state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await? {
        return Ok(false);
    }

    record_balance_charge(provider, state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await?;
    record_account_balance_credit(state, metadata.metadata.contract_executor.clone(), destination.clone(), asset.clone(), amount, payload).await?;

    Ok(true)
}

async fn transfer<'a, 'ty, 'r, P: ContractProvider<'ty>>(instance: FnInstance<'a>, params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    transfer_internal::<P>(instance, params, metadata, context, false).await
        .map(|v| SysCallResult::Return(Primitive::Boolean(v).into()))
}

async fn transfer_payload<'a, 'ty, 'r, P: ContractProvider<'ty>>(instance: FnInstance<'a>, params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    transfer_internal::<P>(instance, params, metadata, context, true).await
        .map(|v| SysCallResult::Return(Primitive::Boolean(v).into()))
}

async fn transfer_contract<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    debug!("Transfer contract called {:?}", params);

    let asset: Hash = params.remove(2)
        .into_owned()
        .into_opaque_type()?;

    let amount = params.remove(1)
        .into_owned()
        .to_u64()?;

    let destination: Hash = params.remove(0)
        .into_owned()
        .into_opaque_type()?;
    {
        let (provider, chain_state) = from_context::<P>(context)?;
        // verify that the contract exists
        if !provider.has_contract(&destination, chain_state.topoheight).await? {
            return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
        }
    }

    let (provider, state) = from_context::<P>(context)?;

    if amount == 0 {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    if !has_enough_balance_for_contract(provider, state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await? {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    record_balance_charge(provider, state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await?;
    record_balance_credit(provider, state, destination.clone(), asset.clone(), amount).await?;

    // Add the output
    state.logs.push(ContractLog::TransferContract { contract: metadata.metadata.contract_executor.clone(), destination, amount, asset });

    Ok(SysCallResult::Return(Primitive::Boolean(true).into()))
}

async fn burn<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    let asset: Hash = params.remove(1)
        .into_owned()
        .into_opaque_type()?;
    let amount = params.remove(0)
        .into_owned()
        .to_u64()?;

    // We have to check if the contract has enough balance to transfer
    if amount == 0 {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    if !has_enough_balance_for_contract(provider, state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await? {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    record_balance_charge(provider, state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await?;

    // Track the burn in the circulating supply
    // We expect that the asset changes exists
    record_burned_asset(provider, state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await?;

    Ok(SysCallResult::Return(Primitive::Boolean(true).into()))
}

async fn get_account_balance_for_asset<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    let asset: Hash = params.remove(1)
        .into_owned()
        .into_opaque_type()?;

    let address: Address = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let balance = provider.get_account_balance_for_asset(address.get_public_key(), &asset, state.topoheight).await?
        .map(|(topoheight, ciphertext)| ValueCell::Object(vec![
            Primitive::U64(topoheight).into(),
            Primitive::Opaque(ciphertext.into()).into()
        ]))
        .unwrap_or_default();

    Ok(SysCallResult::Return(balance.into()))
}

fn get_gas_usage(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let gas = context.current_gas_usage();
    Ok(SysCallResult::Return(Primitive::U64(gas).into()))
}

fn get_gas_limit(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let gas = context.get_gas_limit();
    Ok(SysCallResult::Return(Primitive::U64(gas).into()))
}

// Increase the gas limit using contract balance
async fn increase_gas_limit<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let amount = params[0].as_u64()?;

    // Ensure we're still below the TX max usage
    let below_limit = context.get_gas_limit()
        .checked_add(amount)
        .map_or(false, |gas| gas <= MAX_GAS_USAGE_PER_TX);

    // Zero amount is rejected
    if amount == 0 || !below_limit {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into())); 
    }

    let (provider, state) = from_context::<P>(context)?;

    // We have to ensure that before the deposit with current invoke,
    // we currently have ENOUGH coins before any deposit, contract transfer and such
    // For this, we check in the global cache which is the current cache state before
    // the invoke but still up to date with others (valid) changes that occured.
    // This is required to prevent free-invoke attacks where the contract pay a high gas fee
    // and emit an error on purpose to get fully refunded.
    // Even if the contract is exiting with an error to not apply changes, the code has been executed
    // and gas limit will be paid to the miners
    {
        // Ensure that we check against the overall amount
        let mut total_amount = amount;
        if let Some(amount) = state.injected_gas.get(&Source::Contract(metadata.metadata.contract_executor.clone())).copied() {
            total_amount = amount.checked_add(total_amount)
                .context("Overflow while checking injected gas")?;
        }

        // We look in the global caches as it is the fixed & valid state before this invoke
        // This doesn't contains any of our spending, or any of our deposits
        // so we check it against the full amount
        let balance = match state.global_caches.get(&metadata.metadata.contract_executor)
            .and_then(|cache| cache.balances.get(&XELIS_ASSET).map(Option::as_ref).flatten()) {
                Some((_, balance)) => *balance,
                None => {
                    let (_, balance) = provider.get_contract_balance_for_asset(&metadata.metadata.contract_executor, &XELIS_ASSET, state.topoheight).await?
                        .context("No native balance found for contract")?;
    
                    balance
                }
            };

        // Not enough balance before invoke
        if balance < total_amount {
            return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
        }
    }

    // And we check with current cache if any and then apply if correct
    if !has_enough_balance_for_contract(provider, state, metadata.metadata.contract_executor.clone(), XELIS_ASSET, amount).await? {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    record_balance_charge(provider, state, metadata.metadata.contract_executor.clone(), XELIS_ASSET, amount).await?;

    // Track that each contract have injected N gas
    let injected = state.injected_gas
        .entry(Source::Contract(metadata.metadata.contract_executor.clone()))
        .or_insert(0);
    *injected = injected.checked_add(amount)
        .context("Overflow while tracking injected gas")?;

    context.increase_gas_limit(amount)?;

    Ok(SysCallResult::Return(Primitive::Boolean(true).into()))
}

fn get_current_topoheight(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state: &ChainState = context.get()
        .context("ChainState not present in Context")?;

    Ok(SysCallResult::Return(Primitive::U64(state.topoheight).into()))
}

// Returns the address that called this contract if any
fn get_caller(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state: &ChainState = context.get()
        .context("ChainState not present in Context")?;

    let mainnet = state.mainnet;
    if let Some(source) = state.caller.get_source() {
        let address = source.as_address(mainnet);
        return Ok(SysCallResult::Return(Primitive::Opaque(address.into()).into()));
    }

    Ok(SysCallResult::Return(Primitive::Null.into()))
}

fn get_cost_per_asset(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    Ok(SysCallResult::Return(Primitive::U64(COST_PER_ASSET).into()))
}

fn get_cost_per_scheduled_execution(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    Ok(SysCallResult::Return(Primitive::U64(COST_PER_SCHEDULED_EXECUTION).into()))
}

fn is_contract_callable<'a, 'ty, 'r>(_: FnInstance<'a>, params: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let state: &ChainState = context.get()
        .context("chain state not found")?;

    let contract: &Hash = params[0]
        .as_ref()
        .as_opaque_type()?;

    let chunk_id = params[1]
        .as_ref()
        .to_u16()?;

    let callable = state.permission.allows(contract, chunk_id);

    Ok(SysCallResult::Return(Primitive::Boolean(callable).into()))
}

fn xor_hashes<'a, 'ty, 'r>(_: FnInstance<'a>, params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let hash1: &Hash = params[0]
        .as_ref()
        .as_opaque_type()?;

    let hash2: &Hash = params[1]
        .as_ref()
        .as_opaque_type()?;


    let mut bytes = [0u8; 32];
    for (out, (a, b)) in bytes.iter_mut().zip(hash1.as_bytes().iter().zip(hash2.as_bytes().iter())) {
        *out = a ^ b;
    }

    Ok(SysCallResult::Return(Primitive::Opaque(Hash::new(bytes).into()).into()))
}