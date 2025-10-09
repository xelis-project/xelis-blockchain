use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult
};
use crate::{
    config::FEE_PER_BYTE_IN_CONTRACT_MEMORY,
    contract::{get_cache_for_contract, get_optional_cache_for_contract, ChainState, ContractProvider, ModuleMetadata},
};
use super::{Serializer, MAX_KEY_SIZE, MAX_VALUE_SIZE};

// Shareable data across invoke call on the same Contract in the same Block
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueMemoryStorage {
    // is the storage shared across the TXs from same contract?
    shared: bool,
}

impl Serializable for OpaqueMemoryStorage {}

impl JSONHelper for OpaqueMemoryStorage {}

pub fn memory_storage(_: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let shared = params[0]
        .as_ref()
        .as_bool()?;

    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueMemoryStorage {
        shared,
    })).into()))
}

pub fn is_shared(instance: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    Ok(SysCallResult::Return(Primitive::Boolean(storage.shared).into()))
}

pub fn memory_storage_load<P: ContractProvider>(instance: FnInstance, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_owned();

    let value = get_optional_cache_for_contract(&state.caches, state.global_caches, &metadata.contract)
        .and_then(|cache| if storage.shared {
                &cache.memory_shared
            } else {
                &cache.memory
            }.get(&key).cloned()
        ).unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}

pub fn memory_storage_has<P: ContractProvider>(instance: FnInstance, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_owned();

    let contains = get_optional_cache_for_contract(&state.caches, state.global_caches, &metadata.contract)
        .map_or(false, |cache| if storage.shared {
                &cache.memory_shared
            } else {
                &cache.memory
            }.contains_key(&key)
        );

    Ok(SysCallResult::Return(Primitive::Boolean(contains).into()))
}

pub fn memory_storage_store<P: ContractProvider>(instance: FnInstance, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    let key = params.remove(0)
        .into_owned();

    let key_size = key.size();
    if key_size > MAX_KEY_SIZE {
        return Err(anyhow::anyhow!("Key is too large").into());
    }

    let value = params.remove(0)
        .into_owned();

    let value_size = value.size();
    if value_size > MAX_VALUE_SIZE {
        return Err(anyhow::anyhow!("Value is too large").into());
    }

    let total_size = (key_size + value_size) as u64;
    let cost = total_size * FEE_PER_BYTE_IN_CONTRACT_MEMORY;
    context.increase_gas_usage(cost)?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.contract.clone());
    let memory = if storage.shared {
        &mut cache.memory_shared
    } else {
        &mut cache.memory
    };

    let value = memory.insert(key, value)
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}

pub fn memory_storage_delete<P: ContractProvider>(instance: FnInstance, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_owned();

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.contract.clone());
    let memory = if storage.shared {
        &mut cache.memory_shared
    } else {
        &mut cache.memory
    };

    let value = memory.remove(&key)
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}