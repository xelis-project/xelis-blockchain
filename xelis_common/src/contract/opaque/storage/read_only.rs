use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult
};
use crate::{
    contract::{from_context, ContractProvider, ModuleMetadata},
    crypto::Hash
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueReadOnlyStorage(Hash);

impl JSONHelper for OpaqueReadOnlyStorage {}

impl Serializable for OpaqueReadOnlyStorage {}

pub async fn read_only_storage<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut parameters: FnParams, _: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let hash: Hash = parameters.remove(0)
        .into_owned()
        .into_opaque_type()?;

    if !state.global_caches.contains_key(&hash) && !storage.has_contract(&hash, state.topoheight).await? {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueReadOnlyStorage(hash))).into()))
}

pub async fn read_only_storage_load<'a, 'ty, 'r, P: ContractProvider>(zelf: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let zelf: &OpaqueReadOnlyStorage = zelf?
        .as_opaque_type()?;

    let key = params.remove(0)
        .into_owned();

    // Read from global cache first, then fallback to provider
    let value = match state.global_caches.get(&zelf.0)
        .and_then(|cache| cache.storage.get(&key).map(|(_, v)| v)) {
            Some(v) => v.clone(),
            None => storage.load_data(&zelf.0, &key, state.topoheight).await?
                .map(|(_, v)| v)
                .flatten()
    };

    Ok(SysCallResult::Return(value.unwrap_or_default().into()))
}

pub async fn read_only_storage_has<'a, 'ty, 'r, P: ContractProvider>(zelf: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (storage, state) = from_context::<P>(context)?;
    let zelf: &OpaqueReadOnlyStorage = zelf?
        .as_opaque_type()?;

    let key = params.remove(0)
        .into_owned();

    // Read from global cache first, then fallback to provider
    let contains = match state.global_caches.get(&zelf.0)
        .and_then(|cache| cache.storage.get(&key).map(|(_, v)| v)) {
            Some(v) => v.is_some(),
            None => storage.has_data(&zelf.0, &key, state.topoheight).await?
    };

    Ok(SysCallResult::Return(Primitive::Boolean(contains).into()))
}