use std::{collections::{VecDeque, hash_map::Entry}, hash, sync::Arc};

use indexmap::IndexMap;
use log::debug;
use xelis_vm::{
    VMContext,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    ModuleValidator,
    Primitive,
    Reference,
    SysCallResult,
    traits::{JSONHelper, Serializable}
};
use crate::{
    contract::{
        from_context,
        has_enough_balance_for_contract,
        record_balance_charge,
        record_balance_credit,
        ContractProvider,
        ContractMetadata,
        ModuleMetadata,
        ContractModule
    },
    versioned::VersionedState,
    crypto::Hash,
    transaction::ContractDeposit
};

#[derive(Clone, Debug)]
pub struct OpaqueContract {
    // Contract hash
    pub hash: Hash,
    // Actual module
    pub contract_module: ContractModule,
}

impl PartialEq for OpaqueContract {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for OpaqueContract {}

impl hash::Hash for OpaqueContract {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl Serializable for OpaqueContract {}

impl JSONHelper for OpaqueContract {}

pub async fn contract_new<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    let contract: Hash = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    // Load the module from the provider
    let module = match state.global_modules.get(&contract) {
        Some(v) => v.as_ref().map(|(_, m)| m.as_ref().map(|m| m.as_ref())),
        None => {
            // Not found in cache, lets check in mutable cache
            match state.loaded_modules.entry(contract.clone()) {
                Entry::Occupied(e) => match e.into_mut() {
                    Some((_, m)) => Some(m.as_ref()),
                    None => None,
                },
                Entry::Vacant(e) => {
                    // Load from provider
                    let res = provider.load_contract_module(&contract, state.topoheight).await?
                        .map(|(topo, module)| (VersionedState::FetchedAt(topo), module));

                    e.insert(res).as_ref().map(|(_, m)| m.as_ref())
                }
            }
        },
    }.flatten().cloned();

    let Some(contract_module) = module else {
        return Ok(SysCallResult::Return(Primitive::Null.into()));
    };

    let opaque = OpaqueContract {
        contract_module,
        hash: contract,
    };
    Ok(SysCallResult::Return(opaque.into()))
}

pub async fn contract_call<'a, 'ty, 'r, P: ContractProvider>(zelf: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, context: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let opaque: &OpaqueContract = zelf.as_opaque_type()?;

    let (provider, chain_state) = from_context::<P>(context)?;

    let assets = params.remove(2)
        .into_owned()
        .to_map()?;

    let p = params.remove(1)
        .into_owned()
        .to_vec()?;

    if p.len() > (u8::MAX - 1) as usize {
        return Err(EnvironmentError::Static("Too many parameters"));
    }

    let chunk_id = params.remove(0)
        .into_owned()
        .as_u16()?;

    if !opaque.contract_module.module.is_public_chunk(chunk_id as usize) {
        return Err(EnvironmentError::Static("Chunk is not public"));
    }

    // Check if we have permission to call this contract
    if !chain_state.permission.allows(&opaque.hash, chunk_id) {
        return Err(EnvironmentError::Static("Permission denied to call this contract"));
    }

    // For backward compatibility, we need to switch the environment
    let environment = if metadata.metadata.contract_version != opaque.contract_module.version {
        debug!("Contract version is different between caller ({}) and callee ({}).", metadata.metadata.contract_version, opaque.contract_module.version);
        Some(
            chain_state
                .environments
                .get(&opaque.contract_module.version)
                .cloned()
                .ok_or(EnvironmentError::Static("Contract environment not found"))?
        )
    } else {
        None
    };

    // Verify the chunk and parameters before executing the contract
    let validator = ModuleValidator::new(&opaque.contract_module.module, environment.as_ref().map_or(&metadata.environment, |e| &e));
    validator.verify_invoke_chunk(chunk_id as usize, p.iter().map(|v| v.as_ref()))
        .map_err(|e| {
            debug!("Contract call {} chunk {} validation failed from {}: {}", opaque.hash, chunk_id, metadata.metadata.contract_executor, e);
            EnvironmentError::Static("Invalid parameters for contract call")
        })?;

    let mut deposits = IndexMap::new();
    for (k, v) in assets {
        let asset: Hash = k.into_opaque_type()?;
        let amount = v.as_ref().as_u64()?;

        if amount == 0 {
            return Err(EnvironmentError::Static("amount is zero"));
        }

        if !has_enough_balance_for_contract(provider, chain_state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await? {
            return Err(EnvironmentError::Static("Insufficient funds for deposit"));
        }

        // Insert the deposit to the called contract
        record_balance_charge(provider, chain_state, metadata.metadata.contract_executor.clone(), asset.clone(), amount).await?;
        record_balance_credit(provider, chain_state, opaque.hash.clone(), asset.clone(), amount).await?;

        debug!("Transfering {} of {} to {} from {}", amount, asset, opaque.hash, metadata.metadata.contract_executor);
        deposits.insert(asset, ContractDeposit::Public(amount));
    }

    let p = p.into_iter()
        .rev()
        .map(|v| v.as_ref().clone().into())
        .collect::<VecDeque<_>>();

    Ok(SysCallResult::ModuleCall {
        module: opaque.contract_module.module.clone(),
        metadata: Arc::new(ContractMetadata {
            contract_executor: opaque.hash.clone(),
            contract_version: opaque.contract_module.version,
            contract_caller: Some(metadata.metadata.contract_executor.clone()),
            deposits,
        }),
        environment,
        chunk: chunk_id,
        params: p,
    })
}

pub async fn contract_delegate<'a, 'ty, 'r>(zelf: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata<'_>, _: &mut VMContext<'ty, 'r>) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let opaque: &OpaqueContract = zelf.as_opaque_type()?;
    let p = params.remove(1)
        .into_owned()
        .to_vec()?
        .into_iter()
        .rev()
        .map(|v| v.to_owned().into())
        .collect::<VecDeque<_>>();

    let chunk_id = params.remove(0)
        .into_owned()
        .as_u16()?;

    if !opaque.contract_module.module.is_public_chunk(chunk_id as usize) {
        return Err(EnvironmentError::Static("Chunk is not public"));
    }

    Ok(SysCallResult::ModuleCall {
        module: opaque.contract_module.module.clone(),
        // Reuse the metadata from the module
        metadata: match &metadata.metadata {
            Reference::Borrowed(v) => Arc::new((**v).clone()),
            Reference::Shared(v) => v.clone(),
        },
        // Environment stay the same as we have currently
        environment: None,
        chunk: chunk_id,
        params: p,
    })
}

pub fn contract_get_hash<'a>(zelf: FnInstance<'a>, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext<'_, '_>) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let opaque: &OpaqueContract = zelf.as_opaque_type()?;

    Ok(SysCallResult::Return(opaque.hash.clone().into()))
}