use std::hash;

use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
    ValueCell
};
use crate::{
    config::{COST_PER_DELAYED_EXECUTION, FEE_PER_BYTE_STORED_CONTRACT, XELIS_ASSET},
    contract::{from_context, get_balance_from_cache, get_mut_balance_for_contract, record_burned_asset, ContractProvider, ModuleMetadata, MAX_VALUE_SIZE},
    crypto::Hash,
    serializer::*
};

// Delayed executions are unique per contract
#[derive(Debug, Serialize, Deserialize)]
pub struct DelayedExecution {
    // Contract hash of the module
    pub contract: Hash,
    // Chunk id
    pub chunk_id: u16,
    // Parameters to give for the invoke
    pub params: Vec<ValueCell>,
    // Max gas available to the execution
    // the remaining gas will be paid back to
    // the contract balance
    pub max_gas: u64,
}

impl hash::Hash for DelayedExecution {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
    }
}

impl PartialEq for DelayedExecution {
    fn eq(&self, other: &Self) -> bool {
        self.contract == other.contract
    }
}

impl Eq for DelayedExecution {}

impl Serializer for DelayedExecution {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self {
            contract: Hash::read(reader)?,
            chunk_id: u16::read(reader)?,
            params: Vec::read(reader)?,
            max_gas: u64::read(reader)?,
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.contract.write(writer);
        self.chunk_id.write(writer);
        self.params.write(writer);
        self.max_gas.write(writer);
    }
}

#[derive(Debug, Clone)]
pub struct OpaqueDelayedExecution;

impl PartialEq for OpaqueDelayedExecution {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl Eq for OpaqueDelayedExecution {}

impl hash::Hash for OpaqueDelayedExecution {
    fn hash<H: hash::Hasher>(&self, _: &mut H) {}
}

impl Serializable for OpaqueDelayedExecution {}

impl JSONHelper for OpaqueDelayedExecution {}

pub async fn delayed_execution_new<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, mut params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    let topoheight = params[0]
        .as_u64()?;

    // Only next topoheights are available
    if topoheight <= state.topoheight {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    let chunk_id = params[1]
        .as_u16()?;
    let max_gas = params[2]
        .as_u64()?;

    let params: Vec<ValueCell> = params.remove(3)
        .into_owned()
        .to_vec()?
        .into_iter()
        .map(|v| v.to_owned().into())
        .collect();

    if params.len() > (u8::MAX - 1) as usize {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    let params_size = params.size();
    if params_size > MAX_VALUE_SIZE {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    let burned_part = COST_PER_DELAYED_EXECUTION + (params_size as u64 * FEE_PER_BYTE_STORED_CONTRACT);
    let total_cost =  max_gas + burned_part;

    // Check if we have enough to pay the reserved gas & params fee
    if get_balance_from_cache(provider, state, metadata.contract.clone(), XELIS_ASSET).await?.is_none_or(|(_, balance)| balance < total_cost) {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    if provider.has_delayed_execution_at_topoheight(&metadata.contract, topoheight).await? {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    let execution = DelayedExecution {
        contract: metadata.contract.clone(),
        chunk_id,
        max_gas,
        params,
    };

    if !state.delayed_executions.entry(topoheight)
        .or_insert_with(IndexSet::new)
        .insert(execution) {
        // A delayed execution has been already registered for this
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    // Record the burned part
    record_burned_asset(provider, state, XELIS_ASSET, burned_part).await?;

    // pay the fee
    let (state, balance) = get_mut_balance_for_contract(provider, state, metadata.contract.clone(), XELIS_ASSET).await?;

    state.mark_updated();
    *balance -= total_cost;

    Ok(SysCallResult::Return(Primitive::Boolean(true).into()))
}
