use std::any::TypeId;
use anyhow::bail;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Constant,
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Opaque,
    OpaqueWrapper,
    Value, ValueCell
};
use crate::{
    block::TopoHeight,
    config::{FEE_PER_BYTE_STORED_CONTRACT, FEE_PER_STORE_CONTRACT},
    contract::{from_context, ContractProvider},
    crypto::Hash,
    versioned_type::VersionedState
};
use super::Serializer;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueStorage;

// Maximum size of a value in the storage
pub const MAX_VALUE_SIZE: usize = 4096;

// Maximum size of a key in the storage
pub const MAX_KEY_SIZE: usize = 256;

pub trait ContractStorage {
    // load a value from the storage
    fn load(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<Option<(TopoHeight, Option<Constant>)>, anyhow::Error>;

    // load the latest topoheight from the storage
    fn load_latest_topoheight(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<Option<TopoHeight>, anyhow::Error>;

    // check if a key exists in the storage
    fn has(&self, contract: &Hash, key: &Constant, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;
}

impl JSONHelper for OpaqueStorage {
    fn get_type_name(&self) -> &'static str {
        "Storage"
    }

    fn serialize_json(&self) -> Result<serde_json::Value, anyhow::Error> {
        bail!("Storage serialization is not supported")
    }

    fn is_json_supported(&self) -> bool {
        false
    }
}

impl Serializable for OpaqueStorage {
    fn is_serializable(&self) -> bool {
        false
    }
}

impl Opaque for OpaqueStorage {
    fn get_type(&self) -> TypeId {
        TypeId::of::<OpaqueStorage>()
    }

    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }
}

pub fn storage(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Value::Opaque(OpaqueWrapper::new(OpaqueStorage)).into()))
}

pub fn storage_load<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;

    let value = match state.cache.storage.get(&key) {
        Some((_, value)) => value.clone(),
        None => match storage.load(&state.contract, &key, state.topoheight)? {
            Some((topoheight, constant)) => {
                state.cache.storage.insert(key.clone(), (VersionedState::FetchedAt(topoheight), constant.clone()));
                constant
            },
            None => None
        }
    };

    Ok(Some(ValueCell::Optional(value.map(|c| c.into())).into()))
}

pub fn storage_has<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;

    let contains = match state.cache.storage.get(&key) {
        Some((_, value)) => value.is_some(),
        None => storage.has(state.contract, &key, state.topoheight)?
    };

    Ok(Some(Value::Boolean(contains).into()))
}

pub fn storage_store<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let key: Constant = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;

    let key_size = key.size();
    if key_size > MAX_KEY_SIZE {
        return Err(anyhow::anyhow!("Key is too large").into());
    }

    let value: Constant = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid value"))?;

    let value_size = value.size();
    if value_size > MAX_VALUE_SIZE {
        return Err(anyhow::anyhow!("Value is too large").into());
    }

    let total_size = (key_size + value_size) as u64;
    let cost = FEE_PER_STORE_CONTRACT + total_size * FEE_PER_BYTE_STORED_CONTRACT;
    context.increase_gas_usage(cost)?;

    let (storage, state) = from_context::<P>(context)?;

    let data_state = match state.cache.storage.get(&key) {
        Some((state, _)) => match state {
            VersionedState::New => VersionedState::New,
            VersionedState::FetchedAt(topoheight) => VersionedState::Updated(*topoheight),
            VersionedState::Updated(topoheight) => VersionedState::Updated(*topoheight),
        },
        None => {
            // We need to retrieve the latest topoheight version
            storage.load_latest_topoheight(&state.contract, &key, state.topoheight)?
                .map(|topoheight| VersionedState::Updated(topoheight))
                .unwrap_or(VersionedState::New)
        }
    };

    state.cache.storage.insert(key, (data_state, Some(value)));

    Ok(None)
}

pub fn storage_delete<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;

    let key = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;

    let data_state = match state.cache.storage.get(&key) {
        Some((s, _)) => match s {
            VersionedState::New => {
                state.cache.storage.remove(&key);
                return Ok(None);
            },
            VersionedState::FetchedAt(topoheight) => VersionedState::Updated(*topoheight),
            VersionedState::Updated(topoheight) => VersionedState::Updated(*topoheight),
        },
        None => {
            // We need to retrieve the latest topoheight version
            match storage.load_latest_topoheight(&state.contract, &key, state.topoheight)? {
                Some(topoheight) => VersionedState::Updated(topoheight),
                None => return Ok(None),
            }
        }
    };

    state.cache.storage.insert(key, (data_state, None));

    Ok(None)
}