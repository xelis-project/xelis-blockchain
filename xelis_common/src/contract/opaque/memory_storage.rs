use xelis_vm::{
    RuntimeValue,
    Heap,
    Opaque,
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
    EnvironmentError
};
use crate::{
    block::BlockVersion,
    config::FEE_PER_BYTE_IN_CONTRACT_MEMORY,
    contract::{
        ContractMetadata,
        ContractProvider,
        ModuleMetadata,
        state_from_context,
        check_storage_entry_size,
        get_cache_for_contract,
        get_optional_cache_for_contract
    },
};

// Shareable data across invoke call on the same Contract in the same Block
#[derive(Debug, Clone, PartialEq, Eq, Hash, Opaque)]
#[opaque(hash, eq)]
pub struct OpaqueMemoryStorage {
    // is the storage shared across the TXs from same contract?
    shared: bool,
}

pub fn memory_storage(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let shared = params[0]
        .as_ref(heap)
        .as_bool()?;

    Ok(SysCallResult::Return(RuntimeValue::Opaque(OpaqueMemoryStorage {
        shared,
    }.into()).into()))
}

pub fn is_shared(instance: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage = instance.as_opaque_type::<OpaqueMemoryStorage>(heap)?.clone();

    Ok(SysCallResult::Return(Primitive::Boolean(storage.shared).into()))
}

pub fn memory_storage_load<'ty, P: ContractProvider<'ty>>(instance: FnInstance, params: FnParams<'_>, metadata: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage = instance.as_opaque_type::<OpaqueMemoryStorage>(heap)?.clone();

    let state = state_from_context(context)?;

    let key = heap.export(params.remove(0))?;

    if !key.is_hashable() {
        return Err(EnvironmentError::Static("Key is not hashable"))
    }

    let value = get_optional_cache_for_contract(&state.changes.caches, state.global_caches, &metadata.metadata.contract_executor)
        .and_then(|cache| if storage.shared {
                &cache.memory_shared
            } else {
                &cache.memory
            }.get(&key)
            .cloned()
        ).unwrap_or_default();

    Ok(SysCallResult::Return(heap.import_owned(value).into()))
}

pub fn memory_storage_has<'ty, P: ContractProvider<'ty>>(instance: FnInstance, params: FnParams<'_>, metadata: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage = instance.as_opaque_type::<OpaqueMemoryStorage>(heap)?.clone();

    let state = state_from_context(context)?;

    let key = heap.export(params.remove(0))?;

    if !key.is_hashable() {
        return Err(EnvironmentError::Static("Key is not hashable"))
    }

    let contains = get_optional_cache_for_contract(&state.changes.caches, state.global_caches, &metadata.metadata.contract_executor)
        .map_or(false, |cache| if storage.shared {
                &cache.memory_shared
            } else {
                &cache.memory
            }.contains_key(&key)
        );

    Ok(SysCallResult::Return(Primitive::Boolean(contains).into()))
}

pub fn memory_storage_store<'ty, P: ContractProvider<'ty>>(instance: FnInstance, params: FnParams<'_>, metadata: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage = instance.as_opaque_type::<OpaqueMemoryStorage>(heap)?.clone();

    let value = heap.export(params.remove(1))?;

    let key = heap.export(params.remove(0))?;

    if !key.is_hashable() {
        return Err(EnvironmentError::Static("Key is not hashable"))
    }

    let total_size = check_storage_entry_size(&key, &value)?;
    let cost = total_size as u64 * FEE_PER_BYTE_IN_CONTRACT_MEMORY;
    context.increase_gas_usage(cost)?;

    let state = state_from_context(context)?;

    let cache = get_cache_for_contract(
        &mut state.changes.caches,
        state.global_caches,
        metadata.metadata.contract_executor.clone(),
        state.block_version < BlockVersion::V6,
    );
    let memory = if storage.shared {
        &mut cache.memory_shared
    } else {
        &mut cache.memory
    };

    let value = memory.insert(key, value)
        .unwrap_or_default();

    Ok(SysCallResult::Return(heap.import_owned(value).into()))
}

pub fn memory_storage_delete<'ty, P: ContractProvider<'ty>>(instance: FnInstance, params: FnParams<'_>, metadata: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let storage = instance.as_opaque_type::<OpaqueMemoryStorage>(heap)?.clone();

    let state = state_from_context(context)?;

    let key = heap.export(params.remove(0))?;

    if !key.is_hashable() {
        return Err(EnvironmentError::Static("Key is not hashable"))
    }

    let cache = get_cache_for_contract(
        &mut state.changes.caches,
        state.global_caches,
        metadata.metadata.contract_executor.clone(),
        state.block_version < BlockVersion::V6,
    );
    let memory = if storage.shared {
        &mut cache.memory_shared
    } else {
        &mut cache.memory
    };

    let value = memory.remove(&key)
        .unwrap_or_default();

    Ok(SysCallResult::Return(heap.import_owned(value).into()))
}