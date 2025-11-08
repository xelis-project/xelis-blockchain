use anyhow::Context as AnyhowContext;
use log::debug;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult,
    U256
};

use crate::contract::{
    get_cache_for_contract,
    ChainState,
    DeterministicRandom,
    ContractMetadata,
    ModuleMetadata,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpaqueRandom;

impl Serializable for OpaqueRandom {}

impl JSONHelper for OpaqueRandom {}

fn random_fill_buffer(random: Option<&mut DeterministicRandom>, buffer: &mut [u8]) -> anyhow::Result<()> {
    random
        .context("random not initialized")?
        .fill(buffer)
        .context("filling random buffer")
}

pub fn random_fn(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    // Create a deterministic random for the contract
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());

    if cache.random.is_none() {
        debug!("initializing deterministic random");
        // NOTE: the DeterministicRandom is sandboxed PER contract to prevent any cross-contract interference
        cache.random = Some(DeterministicRandom::new(&metadata.metadata.contract_executor, state.block_hash, state.topoheight, &state.caller.get_hash()));
    }

    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueRandom)).into()))
}

pub fn random_u8(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());

    let mut buffer = [0; 1];
    random_fill_buffer(cache.random.as_mut(), &mut buffer)?;
    let value = buffer[0];

    Ok(SysCallResult::Return(Primitive::U8(value).into()))
}

pub fn random_u16(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let mut buffer = [0; 2];
    random_fill_buffer(cache.random.as_mut(), &mut buffer)?;
    let value = u16::from_le_bytes(buffer);

    Ok(SysCallResult::Return(Primitive::U16(value).into()))
}

pub fn random_u32(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let mut buffer = [0; 4];
    random_fill_buffer(cache.random.as_mut(), &mut buffer)?;
    let value = u32::from_le_bytes(buffer);

    Ok(SysCallResult::Return(Primitive::U32(value).into()))
}

pub fn random_u64(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let mut buffer = [0; 8];
    random_fill_buffer(cache.random.as_mut(), &mut buffer)?;
    let value = u64::from_le_bytes(buffer);

    Ok(SysCallResult::Return(Primitive::U64(value).into()))
}

pub fn random_u128(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let mut buffer = [0; 16];
    random_fill_buffer(cache.random.as_mut(), &mut buffer)?;
    let value = u128::from_le_bytes(buffer);

    Ok(SysCallResult::Return(Primitive::U128(value).into()))
}

pub fn random_u256(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let mut buffer = [0; 32];
    random_fill_buffer(cache.random.as_mut(), &mut buffer)?;
    let value = U256::from_le_bytes(buffer);
    Ok(SysCallResult::Return(Primitive::U256(value).into()))
}

pub fn random_bool(_: FnInstance, _: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let mut buffer = [0; 1];
    random_fill_buffer(cache.random.as_mut(), &mut buffer)?;
    let value = buffer[0] & 1 == 1;

    Ok(SysCallResult::Return(Primitive::Boolean(value).into()))
}