use xelis_vm::{
    PrimitiveInteger,
    Opaque,
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult,
    ValueCell
};

use crate::contract::{
    ContractMetadata,
    ModuleMetadata,
    state_from_context,
};
use super::OpaqueTransaction;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Opaque)]
#[opaque(hash, eq)]
pub struct OpaqueBlock;

pub fn block_current(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    Ok(SysCallResult::Return(ValueCell::Opaque(OpaqueWrapper::new(OpaqueBlock)).into()))
}

pub fn block_nonce(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U64(state.block.get_nonce())).into()))
}

pub fn block_timestamp(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U64(state.block.get_timestamp())).into()))
}

pub fn block_miner(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    let miner_address = state.block.get_miner().as_address(state.mainnet);
    Ok(SysCallResult::Return(ValueCell::Opaque(OpaqueWrapper::new(miner_address)).into()))
}

pub fn block_hash(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    Ok(SysCallResult::Return(ValueCell::Opaque(OpaqueWrapper::new(state.block_hash.clone())).into()))
}

pub fn block_version(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;
    Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U8(state.block.get_version() as u8)).into()))
}

pub fn block_tips(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    let tips = state.block.get_tips()
        .iter()
        .map(|tip| ValueCell::Opaque(OpaqueWrapper::new(tip.clone())).into())
        .collect();

    Ok(SysCallResult::Return(ValueCell::Object(tips).into()))
}

pub fn block_transactions_hashes(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    let hashes = state.block.get_txs_hashes()
        .iter()
        .map(|hash| ValueCell::Opaque(OpaqueWrapper::new(hash.clone())).into())
        .collect::<Vec<_>>();

    context.increase_gas_usage(hashes.len() as u64 * 5)?;

    Ok(SysCallResult::Return(ValueCell::Object(hashes).into()))
}

pub fn block_transactions(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    let txs = state.block.get_txs_hashes()
        .iter()
        .zip(state.block.get_transactions())
        .map(|(hash, tx)| ValueCell::Opaque(OpaqueWrapper::new(OpaqueTransaction {
            inner: tx.clone(),
            hash: hash.clone()
        })).into())
        .collect::<Vec<_>>();

    context.increase_gas_usage(txs.len() as u64 * 10)?;

    Ok(SysCallResult::Return(ValueCell::Object(txs).into()))
}

pub fn block_transactions_count(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U32(state.block.get_txs_count() as u32)).into()))
}

pub fn block_height(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U64(state.block.get_height())).into()))
}

pub fn block_extra_nonce(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let state = state_from_context(context)?;

    let extra_nonce = state.block.get_extra_nonce()
        .to_vec();

    Ok(SysCallResult::Return(ValueCell::Bytes(extra_nonce).into()))
}