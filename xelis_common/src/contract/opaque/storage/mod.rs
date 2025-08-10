mod read_only;

use async_trait::async_trait;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
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
    contract::{from_context, get_cache_for_contract, ContractProvider, ModuleMetadata},
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

    // check if a key exists in the storage
    async fn has_data(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;

    // check if a contract hash exists in the storage
    async fn has_contract(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;
}

impl JSONHelper for OpaqueStorage {}

impl Serializable for OpaqueStorage {}

pub fn storage(_: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueStorage)).into()))
}

pub async fn storage_load<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned();

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.contract.clone());
    let value = match cache.storage.get(&key) {
        Some((_, value)) => value.clone(),
        None => match storage.load_data(&metadata.contract, &key, state.topoheight).await? {
            Some((topoheight, constant)) => {
                cache.storage.insert(key, (VersionedState::FetchedAt(topoheight), constant.clone()));
                constant
            },
            None => None
        }
    };

    Ok(SysCallResult::Return(value.unwrap_or_default().into()))
}

pub async fn storage_has<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned();

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.contract.clone());
    let contains = match cache.storage.get(&key) {
        Some((_, value)) => value.is_some(),
        None => storage.has_data(&metadata.contract, &key, state.topoheight).await?
    };

    Ok(SysCallResult::Return(Primitive::Boolean(contains).into()))
}

pub async fn storage_store<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
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
    let cost = FEE_PER_STORE_CONTRACT + total_size * FEE_PER_BYTE_STORED_CONTRACT;
    context.increase_gas_usage(cost)?;

    let (storage, state) = from_context::<P>(context)?;

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.contract.clone());
    let data_state = match cache.storage.get(&key) {
        Some((mut state, _)) => {
            state.mark_updated();
            state
        },
        None => {
            // We need to retrieve the latest topoheight version
            storage.load_data_latest_topoheight(&metadata.contract, &key, state.topoheight).await?
                .map(|topoheight| VersionedState::Updated(topoheight))
                .unwrap_or(VersionedState::New)
        }
    };

    let value = cache.storage.insert(key, (data_state, Some(value)))
        .map(|(_, v)| v)
        .flatten()
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}

pub async fn storage_delete<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned();

    let cache = get_cache_for_contract(&mut state.caches, state.global_caches, metadata.contract.clone());
    let data_state = match cache.storage.get(&key) {
        Some((s, _)) => match s {
            VersionedState::New => {
                let value = cache.storage.remove(&key);
                return Ok(SysCallResult::Return(value.map(|(_, v)| v).flatten().unwrap_or_default().into()));
            },
            VersionedState::FetchedAt(topoheight) => VersionedState::Updated(*topoheight),
            VersionedState::Updated(topoheight) => VersionedState::Updated(*topoheight),
        },
        None => {
            // We need to retrieve the latest topoheight version
            match storage.load_data_latest_topoheight(&metadata.contract, &key, state.topoheight).await? {
                Some(topoheight) => VersionedState::Updated(topoheight),
                None => return Ok(SysCallResult::Return(Default::default())),
            }
        }
    };

    let value = cache.storage.insert(key, (data_state, None))
        .map(|(_, v)| v)
        .flatten()
        .unwrap_or_default();

    Ok(SysCallResult::Return(value.into()))
}