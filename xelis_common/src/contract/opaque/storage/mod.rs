mod read_only;

use std::collections::hash_map::Entry;

use async_trait::async_trait;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult,
    ValueCell
};
use crate::{
    block::TopoHeight,
    config::{FEE_PER_BYTE_STORED_CONTRACT, FEE_PER_STORE_CONTRACT},
    contract::{
        from_context,
        get_cache_for_contract,
        ContractProvider,
        ContractMetadata,
        ModuleMetadata,
    },
    crypto::Hash,
    versioned_type::VersionedState
};
use super::Serializer;

pub use read_only::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueStorage;

// Maximum size of a value in the storage
pub const MAX_VALUE_SIZE: usize = 4096;

// Maximum size of a key in the storage
pub const MAX_KEY_SIZE: usize = 256;

#[async_trait]
pub trait ContractStorage {
    // load a value from the storage
    async fn load_data(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<ValueCell>)>, anyhow::Error>;

    // load the latest topoheight from the storage
    async fn load_data_latest_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error>;

    // check if a contract hash exists in the storage
    async fn has_contract(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;
}

impl JSONHelper for OpaqueStorage {}

impl Serializable for OpaqueStorage {}

pub fn storage(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueStorage)).into()))
}

pub async fn storage_load<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned();

    if !key.is_serializable() {
        return Err(EnvironmentError::Static("Key is not serializable"))
    }

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let value = match cache.storage.entry(key.clone()) {
        Entry::Occupied(v) => v.get()
            .as_ref()
            .map(|(_, v)| v.clone())
            .flatten(),
        Entry::Vacant(v) => match storage.load_data(&metadata.metadata.contract_executor, &key, state.topoheight).await? {
            Some((topoheight, constant)) => {
                v.insert(Some((VersionedState::FetchedAt(topoheight), constant.clone())));
                constant
            },
            None => {
                v.insert(None);
                None
            }
        }
    };

    Ok(SysCallResult::Return(value.unwrap_or_default().into()))
}

pub async fn storage_has<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned();

    if !key.is_serializable() {
        return Err(EnvironmentError::Static("Key is not serializable"))
    }

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let contains = match cache.storage.entry(key.clone()) {
        Entry::Occupied(v) => v.get()
            .as_ref()
            .map_or(false, |(_, v)| v.is_some()),
        Entry::Vacant(v) => match storage.load_data(&metadata.metadata.contract_executor, &key, state.topoheight).await? {
            Some((topoheight, constant)) => {
                v.insert(Some((VersionedState::FetchedAt(topoheight), constant)));
                true
            },
            None => {
                v.insert(None);
                false
            }
        }
    };

    Ok(SysCallResult::Return(Primitive::Boolean(contains).into()))
}

pub async fn storage_store<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>) -> FnReturnType<ContractMetadata> {
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

    if !key.is_serializable() || !value.is_serializable() {
        return Err(EnvironmentError::Static("Key / value is not serializable"))
    }

    let total_size = (key_size + value_size) as u64;
    let cost = FEE_PER_STORE_CONTRACT + total_size * FEE_PER_BYTE_STORED_CONTRACT;
    context.increase_gas_usage(cost)?;

    let (storage, state) = from_context::<P>(context)?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());

    // We do it in two times: first we retrieve the VersionedState to update it
    let data_state = match cache.storage.get(&key) {
        Some(Some((mut state, _))) => {
            state.mark_updated();
            state
        },
        Some(None) => VersionedState::New,
        None => {
            // We need to retrieve the latest topoheight version
            storage.load_data_latest_topoheight(&metadata.metadata.contract_executor, &key, state.topoheight).await?
                .map(|topoheight| VersionedState::Updated(topoheight))
                .unwrap_or(VersionedState::New)
        }
    };

    // then, we replace the value if it exists (or simply insert it)
    let value = cache.storage.insert(key, Some((data_state, Some(value))))
        .and_then(|v| v.and_then(|(_, v)| v))
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}

pub async fn storage_delete<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut Context<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (storage, state) = from_context::<P>(context)?;

    // into_owned calls `deep_clone`
    let key = params.remove(0)
        .into_owned();

    if !key.is_serializable() {
        return Err(EnvironmentError::Static("Key is not serializable"))
    }

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.metadata.contract_executor.clone());
    let data_state = match cache.storage.get(&key) {
        Some(Some((s, _))) => match s {
            VersionedState::New => {
                let value = cache.storage.remove(&key)
                    .and_then(|v| v.and_then(|(_, v)| v))
                    .unwrap_or_default();

                return Ok(SysCallResult::Return(value.into()));
            },
            VersionedState::FetchedAt(topoheight) => VersionedState::Updated(*topoheight),
            VersionedState::Updated(topoheight) => VersionedState::Updated(*topoheight),
        },
        Some(None) => return Ok(SysCallResult::Return(Default::default())),
        None => {
            // We need to retrieve the latest topoheight version
            match storage.load_data_latest_topoheight(&metadata.metadata.contract_executor, &key, state.topoheight).await? {
                Some(topoheight) => VersionedState::Updated(topoheight),
                None => return Ok(SysCallResult::Return(Default::default())),
            }
        }
    };

    let value = cache.storage.insert(key, Some((data_state, None)))
        .and_then(|v| v.and_then(|(_, v)| v))
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}