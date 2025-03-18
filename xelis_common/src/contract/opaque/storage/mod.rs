mod read_only;

use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    ValueCell
};
use crate::{
    block::TopoHeight,
    config::{FEE_PER_BYTE_STORED_CONTRACT, FEE_PER_STORE_CONTRACT},
    contract::{from_context, ContractProvider},
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

pub trait ContractStorage {
    // load a value from the storage
    fn load_data(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<ValueCell>)>, anyhow::Error>;

    // load the latest topoheight from the storage
    fn load_data_latest_topoheight(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error>;

    // check if a key exists in the storage
    fn has_data(&self, contract: &Hash, key: &ValueCell, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;

    // check if a contract hash exists in the storage
    fn has_contract(&self, contract: &Hash, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;
}

impl JSONHelper for OpaqueStorage {}

impl Serializable for OpaqueStorage {}

pub fn storage(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(OpaqueStorage)).into()))
}

pub fn storage_load<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned()?;

    let value = match state.cache.storage.get(&key) {
        Some((_, value)) => value.clone(),
        None => match storage.load_data(&state.contract, &key, state.topoheight)? {
            Some((topoheight, constant)) => {
                state.cache.storage.insert(key.clone(), (VersionedState::FetchedAt(topoheight), constant.clone()));
                constant
            },
            None => None
        }
    };

    Ok(Some(value.unwrap_or_default()))
}

pub fn storage_has<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned()?;

    let contains = match state.cache.storage.get(&key) {
        Some((_, value)) => value.is_some(),
        None => storage.has_data(state.contract, &key, state.topoheight)?
    };

    Ok(Some(Primitive::Boolean(contains).into()))
}

pub fn storage_store<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let key = params.remove(0)
        .into_owned()?;

    let key_size = key.size();
    if key_size > MAX_KEY_SIZE {
        return Err(anyhow::anyhow!("Key is too large").into());
    }

    let value = params.remove(0)
        .into_owned()?;

    let value_size = value.size();
    if value_size > MAX_VALUE_SIZE {
        return Err(anyhow::anyhow!("Value is too large").into());
    }

    let total_size = (key_size + value_size) as u64;
    let cost = FEE_PER_STORE_CONTRACT + total_size * FEE_PER_BYTE_STORED_CONTRACT;
    context.increase_gas_usage(cost)?;

    let (storage, state) = from_context::<P>(context)?;

    let data_state = match state.cache.storage.get(&key) {
        Some((mut state, _)) => {
            state.mark_updated();
            state
        },
        None => {
            // We need to retrieve the latest topoheight version
            storage.load_data_latest_topoheight(&state.contract, &key, state.topoheight)?
                .map(|topoheight| VersionedState::Updated(topoheight))
                .unwrap_or(VersionedState::New)
        }
    };

    let value = state.cache.storage.insert(key, (data_state, Some(value)))
        .map(|(_, v)| v)
        .flatten()
        .unwrap_or_default();

    Ok(Some(value))
}

pub fn storage_delete<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned()?;

    let data_state = match state.cache.storage.get(&key) {
        Some((s, _)) => match s {
            VersionedState::New => {
                let value = state.cache.storage.remove(&key);
                return Ok(Some(value.map(|(_, v)| v).flatten().unwrap_or_default()));
            },
            VersionedState::FetchedAt(topoheight) => VersionedState::Updated(*topoheight),
            VersionedState::Updated(topoheight) => VersionedState::Updated(*topoheight),
        },
        None => {
            // We need to retrieve the latest topoheight version
            match storage.load_data_latest_topoheight(&state.contract, &key, state.topoheight)? {
                Some(topoheight) => VersionedState::Updated(topoheight),
                None => return Ok(Some(Default::default())),
            }
        }
    };

    let value = state.cache.storage.insert(key, (data_state, None))
        .map(|(_, v)| v)
        .flatten()
        .unwrap_or_default();

    Ok(Some(value))
}