use std::any::TypeId;

use anyhow::{bail, Context as AnyhowContext};
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
    contract::ChainState,
    crypto::Hash,
    transaction::verify::ContractEnvironment,
};

macro_rules! context {
    ($instance: expr, $context: expr) => {{
        let _: &OpaqueStorage = $instance?.as_opaque_type()?;
        let mut datas = $context.get_many_mut([&TypeId::of::<ContractEnvironment<S>>(), &TypeId::of::<ChainState>()]);

        let environment: &mut ContractEnvironment<'_, S> = datas[0]
            .take()
            .context("Contract Environment is not initialized")?
            .downcast_mut()
            .context("Contract Environment is not initialized correctly")?;

        let storage: &mut S = environment.storage;
        let state: &mut ChainState = datas[1]
            .take()
            .context("Chain state is not initialized")?
            .downcast_mut()
            .context("Chain state is not initialized correctly")?;

        (storage, state)
    }};
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueStorage;

pub trait ContractStorage: 'static {
    // load a value from the storage
    fn load(&mut self, contract: &Hash, key: Constant, topoheight: TopoHeight) -> Result<Option<Constant>, anyhow::Error>;

    // check if a key exists in the storage
    fn has(&self, contract: &Hash, key: Constant, topoheight: TopoHeight) -> Result<bool, anyhow::Error>;
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

pub fn storage_load<S: ContractStorage>(instance: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = context!(instance, context);

    let key = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;

    let value = match state.storage.get(&key) {
        Some(value) => value.clone(),
        None => storage.load(&state.contract, key, state.topoheight)?
    };

    Ok(Some(ValueCell::Optional(value.map(|c| c.into())).into()))
}

pub fn storage_has<S: ContractStorage>(instance: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = context!(instance, context);

    let key = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;

    let contains = match state.storage.get(&key) {
        Some(value) => value.is_some(),
        None => storage.has(state.contract, key, state.topoheight)?
    };

    Ok(Some(Value::Boolean(contains).into()))
}

pub fn storage_store<S: ContractStorage>(instance: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueStorage = instance?.as_opaque_type()?;
    let state: &mut ChainState = context.get_mut()
        .context("Chain state is not initialized")?;

    let key = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;

    let value = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid value"))?;

    state.storage.insert(key, Some(value));

    Ok(None)
}

pub fn storage_delete<S: ContractStorage>(instance: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueStorage = instance?.as_opaque_type()?;
    let state: &mut ChainState = context.get_mut()
        .context("Chain state is not initialized")?;

    let key = params.remove(0)
        .into_owned()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key"))?;

    state.storage.insert(key, None);

    Ok(None)
}