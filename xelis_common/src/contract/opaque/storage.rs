use std::any::TypeId;

use anyhow::bail;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Opaque,
    OpaqueWrapper,
    Value
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueStorage;

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
    let storage = OpaqueStorage;

    Ok(Some(Value::Opaque(OpaqueWrapper::new(storage)).into()))
}

pub fn storage_load(instance: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    todo!()
}

pub fn storage_has(instance: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    todo!()
}

pub fn storage_store(instance: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    Ok(None)
}

pub fn storage_delete(instance: FnInstance, params: FnParams, context: &mut Context) -> FnReturnType {
    todo!()
}