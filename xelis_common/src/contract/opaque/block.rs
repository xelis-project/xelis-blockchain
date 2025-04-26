use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    ValueCell
};

use crate::{block::Block, contract::ChainState};

use super::OpaqueTransaction;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueBlock;

impl JSONHelper for OpaqueBlock {}

impl Serializable for OpaqueBlock {}

pub fn block_current(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(OpaqueBlock)).into()))
}

pub fn block_nonce(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;
    Ok(Some(Primitive::U64(block.get_nonce()).into()))
}

pub fn block_timestamp(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;
    Ok(Some(Primitive::U64(block.get_timestamp()).into()))
}

pub fn block_miner(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;
    let state: &ChainState = context.get().context("chain state not found")?;

    let miner_address = block.get_miner().as_address(state.mainnet);
    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(miner_address)).into()))
}

pub fn block_hash(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &ChainState = context.get().context("chain state not found")?;

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(state.block_hash.clone())).into()))
}

pub fn block_version(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Primitive::U8(block.get_version() as u8).into()))
}

pub fn block_tips(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;

    let tips = block.get_tips()
        .iter()
        .map(|tip| Primitive::Opaque(OpaqueWrapper::new(tip.clone())).into())
        .collect();

    Ok(Some(ValueCell::Array(tips)))
}

pub fn block_transactions_hashes(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;

    let hashes = block.get_txs_hashes()
        .iter()
        .map(|hash| Primitive::Opaque(OpaqueWrapper::new(hash.clone())).into())
        .collect();

    Ok(Some(ValueCell::Array(hashes)))
}

pub fn block_transactions(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;

    let txs = block.get_txs_hashes()
        .iter()
        .zip(block.get_transactions())
        .map(|(hash, tx)| Primitive::Opaque(OpaqueWrapper::new(OpaqueTransaction {
            inner: tx.as_arc(),
            hash: hash.clone()
        })).into())
        .collect();

    Ok(Some(ValueCell::Array(txs)))
}

pub fn block_transactions_count(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;
    Ok(Some(Primitive::U32(block.get_txs_count() as _).into()))
}

pub fn block_height(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;
    Ok(Some(Primitive::U64(block.get_height()).into()))
}

pub fn block_extra_nonce(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let block: &Block = context.get().context("current block not found")?;
    let extra_nonce = block.get_extra_nonce()
        .iter()
        .map(|v| Primitive::U8(*v).into())
        .collect();

    Ok(Some(ValueCell::Array(extra_nonce)))
}