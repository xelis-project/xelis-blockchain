use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Value,
    U256
};

use crate::contract::ChainState;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpaqueRandom;

impl Serializable for OpaqueRandom {
    fn is_serializable(&self) -> bool {
        false
    }
}

impl JSONHelper for OpaqueRandom {
    fn is_json_supported(&self) -> bool {
        false
    }
}

pub fn random_fn(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Value::Opaque(OpaqueWrapper::new(OpaqueRandom)).into()))
}

pub fn random_u8(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let _: &OpaqueRandom = opaque.as_ref()?;

    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 1];
    state.random.fill(&mut buffer).context("filling random buffer")?;

    let value = buffer[0];

    Ok(Some(Value::U8(value).into()))
}

pub fn random_u16(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let _: &OpaqueRandom = opaque.as_ref()?;

    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 2];
    state.random.fill(&mut buffer).context("filling random buffer")?;

    let value = u16::from_le_bytes(buffer);

    Ok(Some(Value::U16(value).into()))
}

pub fn random_u32(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let _: &OpaqueRandom = opaque.as_ref()?;

    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 4];
    state.random.fill(&mut buffer).context("filling random buffer")?;

    let value = u32::from_le_bytes(buffer);

    Ok(Some(Value::U32(value).into()))
}

pub fn random_u64(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let _: &OpaqueRandom = opaque.as_ref()?;

    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 8];
    state.random.fill(&mut buffer).context("filling random buffer")?;

    let value = u64::from_le_bytes(buffer);

    Ok(Some(Value::U64(value).into()))
}

pub fn random_u128(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let _: &OpaqueRandom = opaque.as_ref()?;

    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 16];
    state.random.fill(&mut buffer).context("filling random buffer")?;

    let value = u128::from_le_bytes(buffer);

    Ok(Some(Value::U128(value).into()))
}

pub fn random_u256(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let _: &OpaqueRandom = opaque.as_ref()?;

    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 32];
    state.random.fill(&mut buffer).context("filling random buffer")?;

    let value = U256::from_le_bytes(buffer);
    Ok(Some(Value::U256(value).into()))
}

pub fn random_bool(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let _: &OpaqueRandom = opaque.as_ref()?;

    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 1];
    state.random.fill(&mut buffer).context("filling random buffer")?;

    let value = buffer[0] & 1 == 1;

    Ok(Some(Value::Boolean(value).into()))
}