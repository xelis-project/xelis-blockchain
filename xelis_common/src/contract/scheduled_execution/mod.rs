mod kind;

use std::hash;

use anyhow::Context as _;
use indexmap::IndexMap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use xelis_vm::{
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
    ValueCell,
    traits::{JSONHelper, Serializable}
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
        ChainState,
        Source,
        ContractCaller,
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
    // Kind of scheduled execution
    pub kind: ScheduledExecutionKind,
    // Gas sources done for this scheduled execution
    pub gas_sources: IndexMap<Source, u64>,
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
            kind: ScheduledExecutionKind::read(reader)?,
            gas_sources: IndexMap::read(reader)?,
        })
    }

    fn write(&self, writer: &mut Writer) {
        self.hash.write(writer);
        self.contract.write(writer);
        self.chunk_id.write(writer);
        self.params.write(writer);
        self.max_gas.write(writer);
        self.kind.write(writer);
        self.gas_sources.write(writer);
    }

    fn size(&self) -> usize {
        self.hash.size() +
        self.contract.size() +
        self.chunk_id.size() +
        self.params.size() +
        self.max_gas.size() +
        self.kind.size() +
        self.gas_sources.size()
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
        kind,
        gas_sources: [(Source::Contract(metadata.metadata.contract_executor.clone()), max_gas)].into(),
    };

    // register it

    if !state.scheduled_executions.contains_key(&hash) {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    state.scheduled_executions.insert(hash.clone(), execution);

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

pub fn scheduled_execution_get_max_gas<'a, 'ty, 'r>(
    instance: FnInstance<'a>,
    _: FnParams,
    _: &ModuleMetadata<'_>,
    context: &mut Context<'ty, 'r>,
) -> FnReturnType<ContractMetadata> {
    let state: &ChainState = context.get().context("chain state not found")?;

    let instance = instance?;
    let scheduled_execution: &OpaqueScheduledExecution = instance
        .as_ref()
        .as_opaque_type()?;

    let execution = state.scheduled_executions.get(&scheduled_execution.hash)
        .ok_or(EnvironmentError::Static("scheduled execution not found in cache"))?;

    Ok(SysCallResult::Return(Primitive::U64(execution.max_gas).into()))
}

pub fn scheduled_execution_get_pending<'a, 'ty, 'r>(
    _: FnInstance<'a>,
    params: FnParams,
    metadata: &ModuleMetadata<'_>,
    context: &mut Context<'ty, 'r>,
) -> FnReturnType<ContractMetadata> {
    let state: &ChainState = context.get().context("chain state not found")?;

    let param = &params[0];
    let kind = if !param.is_null() {
        ScheduledExecutionKind::TopoHeight(param.as_u64()?)
    } else {
        ScheduledExecutionKind::BlockEnd
    };

    let hash = hash_multiple(&[
        metadata.metadata.contract_executor.as_bytes(),
        &kind.to_bytes(),
    ]);

    if state.scheduled_executions.contains_key(&hash) {
        Ok(SysCallResult::Return(OpaqueScheduledExecution {
            hash: hash,
            kind,
        }.into()))
    } else {
        Ok(SysCallResult::Return(Primitive::Null.into()))
    }
}

pub async fn scheduled_execution_increase_max_gas<'a, 'ty, 'r, P: ContractProvider>(
    instance: FnInstance<'a>,
    params: FnParams,
    metadata: &ModuleMetadata<'_>,
    context: &mut Context<'ty, 'r>,
) -> FnReturnType<ContractMetadata> {
    let amount = params[0].as_u64()?;
    let use_contract_balance = params[1].as_bool()?;

    let instance = instance?;
    let scheduled_execution: &OpaqueScheduledExecution = instance
        .as_ref()
        .as_opaque_type()?;

    if amount == 0 {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    let (provider, state) = from_context::<P>(context)?;

    if !state.allow_executions {
        return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
    }

    // Pay from the contract balance
    let source = if use_contract_balance {
        // check that we have enough to pay the reserved gas
        if get_balance_from_cache(provider, state, metadata.metadata.contract_executor.clone(), XELIS_ASSET)
            .await?
            .is_none_or(|(_, balance)| balance < amount)
        {
            return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
        }
    
        // Check that the scheduled execution exists and belongs to this contract
        let execution = state.scheduled_executions.get(&scheduled_execution.hash)
            .ok_or(EnvironmentError::Static("scheduled execution not found in cache"))?;

        if execution.contract != metadata.metadata.contract_executor {
            return Ok(SysCallResult::Return(Primitive::Boolean(false).into()));
        }

        // Once passed here, we are safe and can apply changes
        let (versioned_state, balance) =
            get_mut_balance_for_contract(provider, state, metadata.metadata.contract_executor.clone(), XELIS_ASSET)
                .await?;
    
        versioned_state.mark_updated();
        *balance -= amount;

        Source::Contract(metadata.metadata.contract_executor.clone())
    } else {
        let source = match state.caller {
            ContractCaller::Transaction(_, tx) => {
                Source::Account(tx.get_source().clone())
            },
            ContractCaller::Scheduled(_, _) => {
                return Err(EnvironmentError::Static("cannot pay from caller scheduled execution")).into();
            }
        };

        // Pay from the gas allowance
        context.increase_gas_usage(amount)?;

        source
    };

    let (_, state) = from_context::<P>(context)?;

    let execution = state.scheduled_executions.get_mut(&scheduled_execution.hash)
        .ok_or(EnvironmentError::Static("scheduled execution not found in cache"))?;

    // Total max gas allocated to this execution
    execution.max_gas += execution.max_gas.checked_add(amount)
        .ok_or(EnvironmentError::GasOverflow)?;

    if execution.gas_sources.len() >= u16::MAX as usize && !execution.gas_sources.contains_key(&source) {
        return Err(EnvironmentError::Static("too many gas injection sources")).into();
    }

    // Individual gas injected from this source
    // This is used for a better tracking of gas usage per source
    // for refunds and accounting
    let injected_gas = execution.gas_sources.entry(source).or_insert(0);
    *injected_gas = injected_gas.checked_add(amount)
        .ok_or(EnvironmentError::GasOverflow)?;

    Ok(SysCallResult::Return(Primitive::Boolean(true).into()))
}