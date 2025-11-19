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
    contract::{
        ChainState,
        ContractMetadata,
        ContractProvider,
        ModuleMetadata,
        check_storage_entry_size,
        get_cache_for_contract,
        get_optional_cache_for_contract
    },
};

// Shareable data across invoke call on the same Contract in the same Block
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueMemoryStorage {
    // is the storage shared across the TXs from same contract?
    shared: bool,
}

impl Serializable for OpaqueMemoryStorage {}

impl JSONHelper for OpaqueMemoryStorage {}

pub fn memory_storage(_: FnInstance, params: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let shared = params[0]
        .as_ref()
        .as_bool()?;

    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueMemoryStorage {
        shared,
    })).into()))
}

pub fn is_shared(instance: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    Ok(SysCallResult::Return(Primitive::Boolean(storage.shared).into()))
}

pub fn memory_storage_load<P: ContractProvider>(instance: FnInstance, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_owned();

    let value = get_optional_cache_for_contract(&state.caches, state.global_caches, &metadata.metadata.contract_executor)
        .and_then(|cache| if storage.shared {
                &cache.memory_shared
            } else {
                &cache.memory
            }.get(&key).cloned()
        ).unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}

pub fn memory_storage_has<P: ContractProvider>(instance: FnInstance, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_owned();

    let contains = get_optional_cache_for_contract(&state.caches, state.global_caches, &metadata.metadata.contract_executor)
        .map_or(false, |cache| if storage.shared {
                &cache.memory_shared
            } else {
                &cache.memory
            }.contains_key(&key)
        );

    Ok(SysCallResult::Return(Primitive::Boolean(contains).into()))
}

pub fn memory_storage_store<P: ContractProvider>(instance: FnInstance, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    let value = params.remove(1)
        .into_owned();

    let key = params.remove(0)
        .into_owned();

    let total_size = check_storage_entry_size(&key, &value)?;
    let cost = total_size as u64 * FEE_PER_BYTE_IN_CONTRACT_MEMORY;
    context.increase_gas_usage(cost)?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let memory = if storage.shared {
        &mut cache.memory_shared
    } else {
        &mut cache.memory
    };

    let value = memory.insert(key, value)
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}

pub fn memory_storage_delete<P: ContractProvider>(instance: FnInstance, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage: &OpaqueMemoryStorage = instance.as_opaque_type()?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_owned();

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let memory = if storage.shared {
        &mut cache.memory_shared
    } else {
        &mut cache.memory
    };

    let value = memory.remove(&key)
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}