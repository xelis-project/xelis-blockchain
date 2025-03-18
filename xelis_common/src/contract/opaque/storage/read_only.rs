use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive
};
use crate::{
    contract::{from_context, ContractProvider},
    crypto::Hash
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueReadOnlyStorage(Hash);

impl JSONHelper for OpaqueReadOnlyStorage {}

impl Serializable for OpaqueReadOnlyStorage {}

pub fn read_only_storage<P: ContractProvider>(_: FnInstance, mut parameters: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;
    let hash: Hash = parameters.remove(0)
        .into_owned()?
        .into_opaque_type()?;

    if !state.global_caches.contains_key(&hash) && !storage.has_contract(&hash, state.topoheight)? {
        return Ok(Some(Primitive::Null.into()))
    }

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(OpaqueReadOnlyStorage(hash))).into()))
}

pub fn read_only_storage_load<P: ContractProvider>(zelf: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;
    let zelf: &OpaqueReadOnlyStorage = zelf?
        .as_opaque_type()?;

    let key = params.remove(0)
        .into_owned()?;

    // Read from global cache first, then fallback to provider
    let value = match state.global_caches.get(&zelf.0)
        .and_then(|cache| cache.storage.get(&key).map(|(_, v)| v)) {
            Some(v) => v.clone(),
            None => storage.load_data(&zelf.0, &key, state.topoheight)?
                .map(|(_, v)| v)
                .flatten()
    };

    Ok(Some(value.unwrap_or_default()))
}

pub fn read_only_storage_has<P: ContractProvider>(zelf: FnInstance, mut params: FnParams, context: &mut Context) -> FnReturnType {
    let (storage, state) = from_context::<P>(context)?;
    let zelf: &OpaqueReadOnlyStorage = zelf?
        .as_opaque_type()?;

    let key = params.remove(0)
        .into_owned()?;

    // Read from global cache first, then fallback to provider
    let contains = match state.global_caches.get(&zelf.0)
        .and_then(|cache| cache.storage.get(&key).map(|(_, v)| v)) {
            Some(v) => v.is_some(),
            None => storage.has_data(&zelf.0, &key, state.topoheight)?
    };

    Ok(Some(Primitive::Boolean(contains).into()))
}