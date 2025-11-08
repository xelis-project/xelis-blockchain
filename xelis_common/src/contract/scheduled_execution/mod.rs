mod kind;

use std::hash;

use indexmap::IndexSet;
use schemars::JsonSchema;
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
    config::{
        COST_PER_SCHEDULED_EXECUTION,
        COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END,
        FEE_PER_BYTE_IN_CONTRACT_MEMORY,
        FEE_PER_BYTE_STORED_CONTRACT,
        XELIS_ASSET
    },
    contract::{
        from_context,
        get_balance_from_cache,
        get_mut_balance_for_contract,
        record_burned_asset,
        ContractLog,
        ContractProvider,
        ContractMetadata,
        ModuleMetadata,
        MAX_VALUE_SIZE
    },
    crypto::{
        hash_multiple,
        Hash
    },
    serializer::*
};

pub use kind::*;

// Scheduled executions are unique per contract
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
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
pub struct OpaqueScheduledExecution {
    kind: ScheduledExecutionKind,
    hash: Hash,
}

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

async fn schedule_execution<'a, 'ty, 'r, P: ContractProvider>(
    kind: ScheduledExecutionKind,
    _: FnInstance<'a>,
    params: FnParams,
    metadata: &ModuleMetadata<'_>,
    context: &mut Context<'ty, 'r>
) -> FnReturnType<ContractMetadata> {
    let (provider, state) = from_context::<P>(context)?;

    match kind {
        ScheduledExecutionKind::TopoHeight(topoheight) => {
            if topoheight <= state.topoheight {
                return Ok(SysCallResult::Return(Primitive::Null.into()));
            }

            if provider.has_scheduled_execution_at_topoheight(&metadata.metadata.contract_executor, topoheight).await? {
                return Ok(SysCallResult::Return(Primitive::Null.into()));
            }
        }
        ScheduledExecutionKind::BlockEnd => {
            if !state.allow_executions {
                return Ok(SysCallResult::Return(Primitive::Null.into()));
            }
        }
    }

    let chunk_id = params[0].as_u16()?;
    if !metadata.module.is_callable_chunk(chunk_id as _) {
        return Ok(SysCallResult::Return(Primitive::Null.into()));
    }

    let p = params[1].as_ref().as_vec()?;
    let max_gas = params[2].as_u64()?;

    if p.len() > (u8::MAX - 1) as usize {
        return Ok(SysCallResult::Return(Primitive::Null.into()));
    }

    let params: Vec<ValueCell> = p.iter()
        .map(|v| v.into_owned().into())
        .collect();
    let params_size = params.size();
    if params_size > MAX_VALUE_SIZE {
        return Ok(SysCallResult::Return(Primitive::Null.into()));
    }

    let burned_part = match kind {
        ScheduledExecutionKind::TopoHeight(_) => COST_PER_SCHEDULED_EXECUTION + (params_size as u64 * FEE_PER_BYTE_STORED_CONTRACT),
        ScheduledExecutionKind::BlockEnd => COST_PER_SCHEDULED_EXECUTION_AT_BLOCK_END
            + (params_size as u64 * FEE_PER_BYTE_IN_CONTRACT_MEMORY),
    };

    let total_cost = max_gas + burned_part;

    // check that we have enough to pay the reserved gas & params fee
    if get_balance_from_cache(provider, state, metadata.metadata.contract_executor.clone(), XELIS_ASSET)
        .await?
        .is_none_or(|(_, balance)| balance < total_cost)
    {
        return Ok(SysCallResult::Return(Primitive::Null.into()));
    }

    // build the caller hash
    let hash = hash_multiple(&[
        metadata.metadata.contract_executor.as_bytes(),
        &kind.to_bytes(),
    ]);

    let execution = ScheduledExecution {
        hash: hash.clone(),
        contract: metadata.metadata.contract_executor.clone(),
        chunk_id,
        max_gas,
        params: params.clone(),
    };

    // register it
    let inserted = match kind {
        ScheduledExecutionKind::TopoHeight(topoheight) => {
            state
                .executions_topoheight
                .entry(topoheight)
                .or_insert_with(IndexSet::new)
                .insert(execution)
        }
        ScheduledExecutionKind::BlockEnd => state.executions_block_end.insert(execution),
    };

    if !inserted {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    // Once passed here, we are safe and can apply changes
    // record the burn part
    record_burned_asset(provider, state, metadata.metadata.contract_executor.clone(), XELIS_ASSET, burned_part).await?;

    state.outputs.push(ContractLog::ScheduledExecution {
        contract: metadata.metadata.contract_executor.clone(),
        hash: hash.clone(),
        kind: match kind {
            ScheduledExecutionKind::TopoHeight(topoheight) => ScheduledExecutionKindLog::TopoHeight { topoheight },
            ScheduledExecutionKind::BlockEnd => ScheduledExecutionKindLog::BlockEnd { chunk_id, max_gas, params }
        },
    });

    let (state, balance) =
        get_mut_balance_for_contract(provider, state, metadata.metadata.contract_executor.clone(), XELIS_ASSET)
            .await?;
    state.mark_updated();
    *balance -= total_cost;

    Ok(SysCallResult::Return(OpaqueScheduledExecution {
        kind,
        hash
    }.into()))
}

pub async fn scheduled_execution_new_at_topoheight<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>,
    params: FnParams,
    metadata: &ModuleMetadata<'_>,
    context: &mut Context<'ty, 'r>,
) -> FnReturnType<ContractMetadata> {
    let topoheight = params[3].as_u64()?;
    schedule_execution::<P>(ScheduledExecutionKind::TopoHeight(topoheight), instance, params, metadata, context).await
}

pub async fn scheduled_execution_new_at_block_end<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>,
    params: FnParams,
    metadata: &ModuleMetadata<'_>,
    context: &mut Context<'ty, 'r>,
) -> FnReturnType<ContractMetadata> {
    schedule_execution::<P>(ScheduledExecutionKind::BlockEnd, instance, params, metadata, context).await
}

pub fn scheduled_execution_get_hash(instance: FnInstance<'_>, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let scheduled_execution: &OpaqueScheduledExecution = instance
        .as_ref()
        .as_opaque_type()?;

    Ok(SysCallResult::Return(scheduled_execution.hash.clone().into()))
}

pub fn scheduled_execution_get_topoheight(instance: FnInstance<'_>, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let instance = instance?;
    let scheduled_execution: &OpaqueScheduledExecution = instance
        .as_ref()
        .as_opaque_type()?;

    match scheduled_execution.kind {
        ScheduledExecutionKind::TopoHeight(topoheight) => Ok(SysCallResult::Return(Primitive::U64(topoheight).into())),
        ScheduledExecutionKind::BlockEnd => Ok(SysCallResult::Return(Primitive::Null.into())),
    }
}