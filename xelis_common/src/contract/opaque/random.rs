use anyhow::Context as AnyhowContext;
use log::debug;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    U256
};

use crate::contract::{ChainState, DeterministicRandom};

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

fn random_fill_buffer(random: Option<&mut DeterministicRandom>, buffer: &mut [u8]) -> anyhow::Result<()> {
    random
        .context("random not initialized")?
        .fill(buffer)
        .context("filling random buffer")
}

pub fn random_fn(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {

    // Create a deterministic random for the contract
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    if state.random.is_none() {
        debug!("initializing deterministic random for {}", state.tx_hash);
        state.random = Some(DeterministicRandom::new(state.contract, state.block_hash, state.tx_hash));
    }

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(OpaqueRandom)).into()))
}

pub fn random_u8(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 1];
    random_fill_buffer(state.random.as_mut(), &mut buffer)?;
    let value = buffer[0];

    Ok(Some(Primitive::U8(value).into()))
}

pub fn random_u16(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 2];
    random_fill_buffer(state.random.as_mut(), &mut buffer)?;
    let value = u16::from_le_bytes(buffer);

    Ok(Some(Primitive::U16(value).into()))
}

pub fn random_u32(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 4];
    random_fill_buffer(state.random.as_mut(), &mut buffer)?;
    let value = u32::from_le_bytes(buffer);

    Ok(Some(Primitive::U32(value).into()))
}

pub fn random_u64(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 8];
    random_fill_buffer(state.random.as_mut(), &mut buffer)?;
    let value = u64::from_le_bytes(buffer);

    Ok(Some(Primitive::U64(value).into()))
}

pub fn random_u128(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 16];
    random_fill_buffer(state.random.as_mut(), &mut buffer)?;
    let value = u128::from_le_bytes(buffer);

    Ok(Some(Primitive::U128(value).into()))
}

pub fn random_u256(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 32];
    random_fill_buffer(state.random.as_mut(), &mut buffer)?;
    let value = U256::from_le_bytes(buffer);
    Ok(Some(Primitive::U256(value).into()))
}

pub fn random_bool(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &mut ChainState = context.get_mut()
        .context("chain state not found")?;

    let mut buffer = [0; 1];
    random_fill_buffer(state.random.as_mut(), &mut buffer)?;
    let value = buffer[0] & 1 == 1;

    Ok(Some(Primitive::Boolean(value).into()))
}