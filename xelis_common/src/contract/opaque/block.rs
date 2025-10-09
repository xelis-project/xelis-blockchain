use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult,
    ValueCell
};

use crate::contract::{ChainState, ModuleMetadata};
use super::OpaqueTransaction;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueBlock;

impl JSONHelper for OpaqueBlock {}

impl Serializable for OpaqueBlock {}

pub fn block_current(_: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(OpaqueBlock)).into()))
}

pub fn block_nonce(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    Ok(SysCallResult::Return(Primitive::U64(chain_state.block.get_nonce()).into()))
}

pub fn block_timestamp(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    Ok(SysCallResult::Return(Primitive::U64(chain_state.block.get_timestamp()).into()))
}

pub fn block_miner(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let state: &ChainState = context.get().context("chain state not found")?;

    let miner_address = state.block.get_miner().as_address(state.mainnet);
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(miner_address)).into()))
}

pub fn block_hash(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let state: &ChainState = context.get().context("chain state not found")?;

    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(state.block_hash.clone())).into()))
}

pub fn block_version(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    Ok(SysCallResult::Return(Primitive::U8(chain_state.block.get_version() as u8).into()))
}

pub fn block_tips(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    let tips = chain_state.block.get_tips()
        .iter()
        .map(|tip| Primitive::Opaque(OpaqueWrapper::new(tip.clone())).into())
        .collect();

    Ok(SysCallResult::Return(ValueCell::Object(tips).into()))
}

pub fn block_transactions_hashes(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    let hashes = chain_state.block.get_txs_hashes()
        .iter()
        .map(|hash| Primitive::Opaque(OpaqueWrapper::new(hash.clone())).into())
        .collect();

    Ok(SysCallResult::Return(ValueCell::Object(hashes).into()))
}

pub fn block_transactions(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    let txs = chain_state.block.get_txs_hashes()
        .iter()
        .zip(chain_state.block.get_transactions())
        .map(|(hash, tx)| Primitive::Opaque(OpaqueWrapper::new(OpaqueTransaction {
            inner: tx.clone(),
            hash: hash.clone()
        })).into())
        .collect();

    Ok(SysCallResult::Return(ValueCell::Object(txs).into()))
}

pub fn block_transactions_count(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    Ok(SysCallResult::Return(Primitive::U32(chain_state.block.get_txs_count() as _).into()))
}

pub fn block_height(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    Ok(SysCallResult::Return(Primitive::U64(chain_state.block.get_height()).into()))
}

pub fn block_extra_nonce(_: FnInstance, _: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let chain_state: &ChainState = context.get()
        .context("context not found")?;

    let extra_nonce = chain_state.block.get_extra_nonce()
        .iter()
        .map(|v| Primitive::U8(*v).into())
        .collect();

    Ok(SysCallResult::Return(ValueCell::Object(extra_nonce).into()))
}