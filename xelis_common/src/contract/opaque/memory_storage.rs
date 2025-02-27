use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Constant,
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Value,
    ValueCell
};
use crate::{
    config::FEE_PER_BYTE_IN_CONTRACT_MEMORY,
    contract::{ChainState, ContractProvider},
};
use super::Serializer;

// Shareable data across invoke call on the same Contract in the same Block
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueMemoryStorage;

impl Serializable for OpaqueMemoryStorage {}

impl JSONHelper for OpaqueMemoryStorage {}

// Maximum size of a value in the storage
pub const MAX_VALUE_SIZE: usize = 4096;

// Maximum size of a key in the storage
pub const MAX_KEY_SIZE: usize = 256;

pub fn memory_storage(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Value::Opaque(OpaqueWrapper::new(OpaqueMemoryStorage)).into()))
}

pub fn memory_storage_load<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_inner()
        .try_into()?;

    let value = state.cache.memory.get(&key)
        .cloned();
    Ok(Some(ValueCell::Optional(value.map(Constant::into))))
}

pub fn memory_storage_has<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_inner()
        .try_into()?;

    let contains = state.cache.memory.contains_key(&key);
    Ok(Some(Value::Boolean(contains).into()))
}

pub fn memory_storage_store<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let key: Constant = params.remove(0)
        .into_inner()
        .try_into()?;

    let key_size = key.size();
    if key_size > MAX_KEY_SIZE {
        return Err(anyhow::anyhow!("Key is too large").into());
    }

    let value: Constant = params.remove(0)
        .into_inner()
        .try_into()?;

    let value_size = value.size();
    if value_size > MAX_VALUE_SIZE {
        return Err(anyhow::anyhow!("Value is too large").into());
    }

    let total_size = (key_size + value_size) as u64;
    let cost = total_size * FEE_PER_BYTE_IN_CONTRACT_MEMORY;
    context.increase_gas_usage(cost)?;

    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;
    let value = state.cache.memory.insert(key, value);
    Ok(Some(ValueCell::Optional(value.map(Constant::into))))
}

pub fn memory_storage_delete<P: ContractProvider>(_: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("No chain state for memory storage")?;

    let key = params.remove(0)
        .into_inner()
        .try_into()?;

    let value = state.cache.memory.remove(&key);
    Ok(Some(ValueCell::Optional(value.map(Constant::into))))
}