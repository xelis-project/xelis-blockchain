use std::{collections::{hash_map::Entry, VecDeque}, hash, sync::Arc};

use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Module,
    OpaqueWrapper,
    Primitive,
    StackValue,
    SysCallResult
};
use crate::{
    contract::{from_context, ContractProvider, ModuleMetadata},
    crypto::Hash
};

#[derive(Clone, Debug)]
pub struct OpaqueModule {
    // Contract module hash
    pub contract: Hash,
    // Actual module
    pub module: Arc<Module>
}

impl PartialEq for OpaqueModule {
    fn eq(&self, other: &Self) -> bool {
        self.contract == other.contract
    }
}

impl Eq for OpaqueModule {}

impl hash::Hash for OpaqueModule {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
    }
}

impl Serializable for OpaqueModule {
    fn is_serializable(&self) -> bool {
        false
    }
}

impl JSONHelper for OpaqueModule {
    fn is_json_supported(&self) -> bool {
        false
    }
}

pub async fn module_new<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    let contract: Hash = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    // Load the module from the provider
    let module = match state.modules.entry(contract.clone()) {
        Entry::Occupied(entry) => entry.get().clone(),
        Entry::Vacant(entry) => {
            let module = provider.load_contract_module(&contract, state.topoheight).await?
                .map(|module| OpaqueModule {
                module,
                contract,
            });

            entry.insert(module).clone()
        }
    };

    let Some(module) = module else {
        return Ok(SysCallResult::Return(Primitive::Null.into()));
    };

    Ok(SysCallResult::Return(StackValue::Owned(Primitive::Opaque(OpaqueWrapper::new(module)).into())))
}

pub async fn module_invoke<'a, 'ty, 'r>(zelf: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata, _: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let module: &OpaqueModule = zelf?.as_opaque_type()?;
    let p = params.remove(1)
        .into_owned()
        .to_vec()?
        .into_iter()
        .map(|v| v.to_owned().into())
        .collect::<VecDeque<_>>();

    let chunk_id = params.remove(0)
        .into_owned()
        .as_u16()?;

    Ok(SysCallResult::ModuleCall {
        module: module.module.clone(),
        metadata: Arc::new(ModuleMetadata {
            contract: module.contract.clone(),
            caller: Some(metadata.contract.clone()),
            // TODO: deposits
            deposits: Default::default(),
        }),
        chunk: chunk_id,
        params: p,
    })
}

pub async fn module_delegate<'a, 'ty, 'r>(zelf: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata, _: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let module: &OpaqueModule = zelf?.as_opaque_type()?;
    let p = params.remove(1)
        .into_owned()
        .to_vec()?
        .into_iter()
        .map(|v| v.to_owned().into())
        .collect::<VecDeque<_>>();

    let chunk_id = params.remove(0)
        .into_owned()
        .as_u16()?;

    Ok(SysCallResult::ModuleCall {
        module: module.module.clone(),
        // Reuse the metadata from the module
        metadata: Arc::new(metadata.clone()),
        chunk: chunk_id,
        params: p,
    })
}