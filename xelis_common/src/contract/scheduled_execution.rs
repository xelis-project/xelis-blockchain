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
    config::{COST_PER_SCHEDULED_EXECUTION, COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END, FEE_PER_BYTE_IN_CONTRACT_MEMORY, FEE_PER_BYTE_STORED_CONTRACT, XELIS_ASSET},
    contract::{from_context, get_balance_from_cache, get_mut_balance_for_contract, record_burned_asset, ContractProvider, ModuleMetadata, MAX_VALUE_SIZE},
    crypto::{hash_multiple, Hash},
    serializer::*
};

// Scheduled executions are unique per contract
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScheduledExecution {
    // The current hash representing this scheduled execution
    // It is based on blake3(contract || topoheight)
    // because we only allow one scheduled execution per contract
    // at a specific topoheight
    pub hash: Hash,
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

impl hash::Hash for ScheduledExecution {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.contract.hash(state);
    }
}

impl PartialEq for ScheduledExecution {
    fn eq(&self, other: &Self) -> bool {
        self.contract == other.contract
    }
}

impl Eq for ScheduledExecution {}

impl Serializer for ScheduledExecution {
    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        Ok(Self {
            hash: Hash::read(reader)?,
            contract: Hash::read(reader)?,
            chunk_id: u16::read(reader)?,
            params: Vec::read(reader)?,
            max_gas: u64::read(reader)?,
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.hash.write(writer);
        self.contract.write(writer);
        self.chunk_id.write(writer);
        self.params.write(writer);
        self.max_gas.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size() +
        self.contract.size() +
        self.chunk_id.size() +
        self.params.size() +
        self.max_gas.size()
    }
}

#[derive(Debug, Clone)]
pub struct OpaqueScheduledExecution;

impl PartialEq for OpaqueScheduledExecution {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl Eq for OpaqueScheduledExecution {}

impl hash::Hash for OpaqueScheduledExecution {
    fn hash<H: hash::Hasher>(&self, _: &mut H) {}
}

impl Serializable for OpaqueScheduledExecution {}

impl JSONHelper for OpaqueScheduledExecution {}

pub async fn scheduled_execution_new_at_topoheight<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
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

    let p = params[3]
        .as_ref()
        .as_vec()?;

    if p.len() > (u8::MAX - 1) as usize {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    let params: Vec<ValueCell> = p.iter()
        .map(|v| v.to_owned().into())
        .collect();

    if params.len() > (u8::MAX - 1) as usize {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    let params_size = params.size();
    if params_size > MAX_VALUE_SIZE {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    let burned_part = COST_PER_SCHEDULED_EXECUTION + (params_size as u64 * FEE_PER_BYTE_STORED_CONTRACT);
    let total_cost =  max_gas + burned_part;

    // Check if we have enough to pay the reserved gas & params fee
    if get_balance_from_cache(provider, state, metadata.contract.clone(), XELIS_ASSET).await?.is_none_or(|(_, balance)| balance < total_cost) {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    if provider.has_scheduled_execution_at_topoheight(&metadata.contract, topoheight).await? {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    // Create the hash for this scheduled execution
    let hash = hash_multiple(&[
        metadata.contract.as_bytes(),
        &topoheight.to_le_bytes(),
        &[0u8], // 0 for topoheight
    ]);

    let execution = ScheduledExecution {
        hash,
        contract: metadata.contract.clone(),
        chunk_id,
        max_gas,
        params,
    };

    if !state.scheduled_executions.entry(topoheight)
        .or_insert_with(IndexSet::new)
        .insert(execution) {
        // A delayed execution has been already registered for this
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    // Record the burned part
    record_burned_asset(provider, state, metadata.contract.clone(), XELIS_ASSET, burned_part).await?;

    // pay the fee
    let (state, balance) = get_mut_balance_for_contract(provider, state, metadata.contract.clone(), XELIS_ASSET).await?;

    state.mark_updated();
    *balance -= total_cost;

    Ok(SysCallResult::Return(OpaqueScheduledExecution.into()))
}

pub async fn scheduled_execution_new_at_block_end<'a, 'ty, 'r, P: ContractProvider>(_: FnInstance<'a>, params: FnParams, metadata: &ModuleMetadata, context: &mut Context<'ty, 'r>) -> FnReturnType<ModuleMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    if !state.allow_executions {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    let chunk_id = params[0]
        .as_u16()?;

    let max_gas = params[1]
        .as_u64()?;

    let p = params[2]
        .as_ref()
        .as_vec()?;

    if p.len() > (u8::MAX - 1) as usize {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    let params: Vec<ValueCell> = p.iter()
        .map(|v| v.to_owned().into())
        .collect();

    let params_size = params.size();
    if params_size > MAX_VALUE_SIZE {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    // Lower fee because we don't have to store the execution on disk
    let burned_part = COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END + (params_size as u64 * FEE_PER_BYTE_IN_CONTRACT_MEMORY);
    let total_cost =  max_gas + burned_part;

    // Check if we have enough to pay the reserved gas & params fee
    if get_balance_from_cache(provider, state, metadata.contract.clone(), XELIS_ASSET).await?.is_none_or(|(_, balance)| balance < total_cost) {
        return Ok(SysCallResult::Return(Primitive::Null.into()))
    }

    // Create the hash for this scheduled execution
    let hash = hash_multiple(&[
        metadata.contract.as_bytes(),
        &chunk_id.to_le_bytes(),
        &state.topoheight.to_le_bytes(),
        &[1u8] // 1 for block end
    ]);

    let execution = ScheduledExecution {
        hash,
        contract: metadata.contract.clone(),
        chunk_id,
        max_gas,
        params,
    };

    if !state.planned_executions.insert(execution) {
        // A delayed execution has been already registered for this
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()))
    }

    // Record the burned part
    record_burned_asset(provider, state, metadata.contract.clone(), XELIS_ASSET, burned_part).await?;

    // pay the fee
    let (state, balance) = get_mut_balance_for_contract(provider, state, metadata.contract.clone(), XELIS_ASSET).await?;

    state.mark_updated();
    *balance -= total_cost;

    Ok(SysCallResult::Return(OpaqueScheduledExecution.into()))
}
