use std::collections::hash_map::Entry;

use xelis_vm::{
    traits::{JSONHelper, Serializable},
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult
};
use crate::{
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueReadOnlyStorage(Hash);

impl JSONHelper for OpaqueReadOnlyStorage {}

impl Serializable for OpaqueReadOnlyStorage {}

pub async fn read_only_storage<'a, 'ty, 'r, P: ContractProvider<'ty>>(_: FnInstance<'a>, mut parameters: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let hash: Hash = parameters.remove(0)
        .into_owned()
        .into_opaque_type()?;

    // If we don't have a global cache or an actual local cache for this contract
    // OR the contract does not exist in the storage, we return null
    if get_optional_cache_for_contract(&state.changes.caches, state.global_caches, &hash).is_none() && !storage.has_contract(&hash, state.topoheight).await? {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueReadOnlyStorage(hash))).into()))
}

pub async fn read_only_storage_load<'a, 'ty, 'r, P: ContractProvider<'ty>>(zelf: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let zelf = zelf?;
    let zelf: &OpaqueReadOnlyStorage = zelf
        .as_opaque_type()?;

    let key = params.remove(0)
        .into_owned();

    check_storage_key(&key)?;

    // Read from global cache first, then fallback to provider
    let value = match get_cache_for_contract(&mut state.changes.caches, state.global_caches, zelf.0.clone(), state.cache_clone_refs)
        .storage
        .entry(key.clone_ref()) {
            Entry::Occupied(v) => v.get()
                .as_ref()
                .and_then(|(_, v)| v.as_ref().map(|v| if state.cache_clone_refs {
                    v.clone_ref()
                } else {
                    v.clone()
                })),
            Entry::Vacant(v) => {
                let data = storage.load_data(&zelf.0, &key, state.topoheight).await?
                    .map(|(topo, v)| (VersionedState::FetchedAt(topo), v));

                v.insert(data)
                    .as_ref()
                    .and_then(|(_, v)| v.as_ref().map(|v| if state.cache_clone_refs {
                        v.clone_ref()
                    } else {
                        v.clone()
                    }))
            }
    };

    // We are forced to do a deep clone in case a contract try to attack
    // another contract memory due to how XVM handle references
    Ok(SysCallResult::Return(value.unwrap_or_default().into()))
}

pub async fn read_only_storage_has<'a, 'ty, 'r, P: ContractProvider<'ty>>(zelf: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let zelf = zelf?;
    let zelf: &OpaqueReadOnlyStorage = zelf
        .as_opaque_type()?;

    let key = params.remove(0)
        .into_owned();

    check_storage_key(&key)?;

    // Read from global cache first, then fallback to provider
    let contains = match get_cache_for_contract(&mut state.changes.caches, state.global_caches, zelf.0.clone(), state.cache_clone_refs)
        .storage
        .entry(key.clone_ref()) {
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