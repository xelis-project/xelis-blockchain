mod metadata;
mod opaque;
mod random;

use anyhow::Context as AnyhowContext;
use log::debug;
use opaque::*;
use xelis_builder::EnvironmentBuilder;
use xelis_vm::{
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Type,
    Value
};
use crate::crypto::Hash;

pub use metadata::ContractMetadata;
pub use random::DeterministicRandom;

pub struct ChainState {
    pub debug_mode: bool,
    pub random: DeterministicRandom,
    pub mainnet: bool,
    pub contract: Hash,
}

// Build the environment for the contract
pub fn build_environment() -> EnvironmentBuilder<'static> {
    debug!("Building environment for contract");
    register_opaque_types();

    let mut env = EnvironmentBuilder::default();

    env.get_mut_function("println", None, vec![Type::Any])
        .set_on_call(println_fn);

    // Opaque type but we provide getters
    let tx_type = Type::Opaque(env.register_opaque::<OpaqueTransaction>("Transaction"));
    let hash_type = Type::Opaque(env.register_opaque::<Hash>("Hash"));
    let address_type = Type::Opaque(env.register_opaque::<Hash>("Address"));
    let random_type = Type::Opaque(env.register_opaque::<DeterministicRandom>("Random"));

    env.register_native_function(
        "current_transaction",
        Some(tx_type.clone()),
        vec![],
        current_transaction,
        5,
        Some(Type::U64)
    );
    env.register_native_function(
        "nonce",
        Some(tx_type.clone()),
        vec![],
        transaction_nonce,
        5,
        Some(Type::U64)
    );
    env.register_native_function(
        "hash",
        Some(tx_type.clone()),
        vec![],
        transaction_hash,
        5,
        Some(hash_type.clone())
    );
    env.register_native_function(
        "source",
        Some(tx_type.clone()),
        vec![],
        transaction_source,
        5,
        Some(address_type.clone())
    );
    env.register_native_function(
        "fee",
        Some(tx_type.clone()),
        vec![],
        transaction_fee,
        5,
        Some(Type::U64)
    );

    env.register_native_function(
        "get_contract_hash",
        None,
        vec![],
        get_contract_hash,
        5,
        Some(hash_type.clone())
    );

    env.register_native_function(
        "get_balance_for_asset",
        None,
        vec![("asset", hash_type.clone())],
        get_balance_for_asset,
        5,
        Some(Type::U64)
    );

    env.register_native_function(
        "transfer",
        Some(tx_type.clone()),
        vec![
            ("to", address_type),
            ("amount", Type::U64),
            ("asset", hash_type),
        ],
        transfer,
        5,
        Some(Type::U64)
    );

    // Random number generator
    env.register_native_function(
        "random",
        None,
        vec![],
        random_fn,
        5,
        Some(random_type.clone())
    );
    env.register_native_function(
        "next_u8",
        Some(random_type.clone()),
        vec![],
        random_u8,
        5,
        Some(Type::U8)
    );
    env.register_native_function(
        "next_u16",
        Some(random_type.clone()),
        vec![],
        random_u16,
        5,
        Some(Type::U16)
    );
    env.register_native_function(
        "next_u32",
        Some(random_type.clone()),
        vec![],
        random_u32,
        5,
        Some(Type::U32)
    );
    env.register_native_function(
        "next_u64",
        Some(random_type.clone()),
        vec![],
        random_u64,
        5,
        Some(Type::U64)
    );
    env.register_native_function(
        "next_u128",
        Some(random_type.clone()),
        vec![],
        random_u128,
        5,
        Some(Type::U128)
    );
    env.register_native_function(
        "next_u256",
        Some(random_type.clone()),
        vec![],
        random_u256,
        5,
        Some(Type::U256)
    );
    env.register_native_function(
        "next_bool",
        Some(random_type.clone()),
        vec![],
        random_bool,
        5,
        Some(Type::Bool)
    );

    env
}

fn println_fn(_: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    let state: &ChainState = context.get().context("chain state not found")?;
    if state.debug_mode {
        debug!("{}", params[0].as_ref());
    }

    Ok(None)
}


fn get_contract_hash(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &ChainState = context.get().context("chain state not found")?;
    Ok(Some(Value::Opaque(OpaqueWrapper::new(state.contract.clone())).into()))
}

fn get_balance_for_asset(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(None)
}

fn transfer(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(None)
}