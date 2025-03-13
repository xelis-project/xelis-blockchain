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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueBlock;

impl JSONHelper for OpaqueBlock {}

impl Serializable for OpaqueBlock {}

pub fn block(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(OpaqueBlock)).into()))
}

pub fn block_nonce(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Primitive::U64(block.get_nonce()).into()))
}

pub fn block_timestamp(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Primitive::U64(block.get_timestamp()).into()))
}

pub fn block_miner(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;
    let state: &ChainState = context.get().context("chain state not found")?;

    let miner_address = block.get_miner().as_address(state.mainnet);
    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(miner_address)).into()))
}

pub fn block_hash(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get().context("chain state not found")?;

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(state.block_hash.clone())).into()))
}

pub fn block_version(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Primitive::U8(block.get_version() as u8).into()))
}

pub fn block_tips(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;

    let tips = block.get_tips()
        .iter()
        .map(|tip| Primitive::Opaque(OpaqueWrapper::new(tip.clone())).into())
        .collect();

    Ok(Some(ValueCell::Array(tips)))
}

pub fn block_height(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque()?;
    let _: &OpaqueBlock = opaque.as_ref()?;

    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Primitive::U64(block.get_height()).into()))
}

pub fn block_extra_nonce(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque()?;
    let _: &OpaqueBlock = opaque.as_ref()?;

    let block: &Block = context.get().context("current block not found")?;
    let extra_nonce = block.get_extra_nonce()
        .iter()
        .map(|v| Primitive::U8(*v).into())
        .collect();

    Ok(Some(ValueCell::Array(extra_nonce)))
}