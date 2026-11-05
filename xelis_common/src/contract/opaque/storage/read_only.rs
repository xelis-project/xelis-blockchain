use std::collections::hash_map::Entry;

use xelis_vm::{
    RuntimeValue,
    Heap,
    Opaque,
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult
};
use crate::{
    block::BlockVersion,
    contract::{
        from_context,
        get_cache_for_contract,
        get_optional_cache_for_contract,
        ContractProvider,
        ContractMetadata,
        ModuleMetadata,
    },
    crypto::Hash,
    versioned::VersionedState
};
use super::check_storage_key;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Opaque)]
#[opaque(hash, eq)]
pub struct OpaqueReadOnlyStorage(Hash);

pub async fn read_only_storage<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, parameters: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let hash: Hash = parameters.remove(0).into_owned(heap)?
        .into_opaque_type()?;

    // If we don't have a global cache or an actual local cache for this contract
    // OR the contract does not exist in the storage, we return null
    if get_optional_cache_for_contract(&state.changes.caches, state.global_caches, &hash).is_none() && !storage.has_contract(&hash, state.topoheight).await? {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    Ok(SysCallResult::Return(RuntimeValue::Opaque(OpaqueReadOnlyStorage(hash).into()).into()))
}

pub async fn read_only_storage_load<'a, 'ty, 'r, P: ContractProvider<'ty>>(zelf: FnInstance<'a>, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let zelf = zelf?;
    let zelf = zelf.as_opaque_type::<OpaqueReadOnlyStorage>(heap)?.clone();

    let key = heap.export(params.remove(0))?;

    check_storage_key(&key)?;

    // Read from global cache first, then fallback to provider
    let value = match get_cache_for_contract(&mut state.changes.caches, state.global_caches, zelf.0.clone(), state.block_version < BlockVersion::V6)
        .storage
        .entry(key.clone()) {
            Entry::Occupied(v) => v.get()
                .as_ref()
                .and_then(|(_, v)| v.clone()),
            Entry::Vacant(v) => {
                let data = storage.load_data(&zelf.0, &key, state.topoheight).await?
                    .map(|(topo, v)| (VersionedState::FetchedAt(topo), v));

                v.insert(data)
                    .as_ref()
                    .and_then(|(_, v)| v.clone())
            }
    };

    // We are forced to do a deep clone in case a contract try to attack
    // another contract memory due to how XVM handle references
    Ok(SysCallResult::Return(heap.import_owned(value.unwrap_or_default()).into()))
}

pub async fn read_only_storage_has<'a, 'ty, 'r, P: ContractProvider<'ty>>(zelf: FnInstance<'a>, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let zelf = zelf?;
    let zelf = zelf.as_opaque_type::<OpaqueReadOnlyStorage>(heap)?.clone();

    let key = heap.export(params.remove(0))?;

    check_storage_key(&key)?;

    // Read from global cache first, then fallback to provider
    let contains = match get_cache_for_contract(&mut state.changes.caches, state.global_caches, zelf.0.clone(), state.block_version < BlockVersion::V6)
        .storage
        .entry(key.clone()) {
            Entry::Occupied(v) => v.get()
                .as_ref()
                .map_or(false, |(_, v)| v.is_some()),
            Entry::Vacant(v) => {
                let data = storage.load_data(&zelf.0, &key, state.topoheight).await?
                    .map(|(topo, v)| (VersionedState::FetchedAt(topo), v));

                v.insert(data)
                    .as_ref()
                    .map_or(false, |(_, v)| v.is_some())
            }
    };

    Ok(SysCallResult::Return(Primitive::Boolean(contains).into()))
}