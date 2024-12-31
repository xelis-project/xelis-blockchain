use core::fmt;
use std::any::TypeId;

use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Opaque,
    OpaqueWrapper,
    Value, ValueCell
};

use crate::{block::Block, contract::ChainState};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueBlock;

impl Serializable for OpaqueBlock {
    fn get_size(&self) -> usize {
        1
    }

    fn is_serializable(&self) -> bool {
        false
    }
}

impl JSONHelper for OpaqueBlock {
    fn get_type_name(&self) -> &'static str {
        "Block"
    }

    fn serialize_json(&self) -> Result<serde_json::Value, anyhow::Error> {
        Err(anyhow::anyhow!("Block serialization is not supported"))
    }

    fn is_json_supported(&self) -> bool {
        false
    }
}

impl Opaque for OpaqueBlock {
    fn get_type(&self) -> TypeId {
        TypeId::of::<OpaqueBlock>()
    }

    fn display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Block")
    }

    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }
}

pub fn block(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Value::Opaque(OpaqueWrapper::new(OpaqueBlock)).into()))
}

pub fn block_nonce(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Value::U64(block.get_nonce()).into()))
}

pub fn block_timestamp(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Value::U64(block.get_timestamp()).into()))
}

pub fn block_miner(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;
    let state: &ChainState = context.get().context("chain state not found")?;

    let miner_address = block.get_miner().as_address(state.mainnet);
    Ok(Some(Value::Opaque(OpaqueWrapper::new(miner_address)).into()))
}

pub fn block_hash(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get().context("chain state not found")?;

    Ok(Some(Value::Opaque(OpaqueWrapper::new(state.block_hash.clone())).into()))
}

pub fn block_version(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Value::U8(block.get_version() as u8).into()))
}

pub fn block_tips(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueBlock = zelf?.as_opaque_type()?;
    let block: &Block = context.get().context("current block not found")?;

    let tips = block.get_tips()
        .iter()
        .map(|tip| Value::Opaque(OpaqueWrapper::new(tip.clone())).into())
        .collect();

    Ok(Some(ValueCell::Array(tips)))
}

pub fn block_height(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque()?;
    let _: &OpaqueBlock = opaque.as_ref()?;

    let block: &Block = context.get().context("current block not found")?;

    Ok(Some(Value::U64(block.get_height()).into()))
}

pub fn block_extra_nonce(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque()?;
    let _: &OpaqueBlock = opaque.as_ref()?;

    let block: &Block = context.get().context("current block not found")?;
    let extra_nonce = block.get_extra_nonce()
        .iter()
        .map(|v| Value::U8(*v).into())
        .collect();

    Ok(Some(ValueCell::Array(extra_nonce)))
}