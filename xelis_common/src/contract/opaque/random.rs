use std::{any::TypeId, hash::Hasher};

use anyhow::{bail, Context as AnyhowContext};
use xelis_vm::{traits::{DynEq, DynHash, JSONHelper}, Context, FnInstance, FnParams, FnReturnType, Opaque, OpaqueWrapper, Value, U256};

use crate::contract::{ChainState, DeterministicRandom};

impl Opaque for DeterministicRandom {
    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }

    fn display(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DeterministicRandom")
    }

    fn get_type(&self) -> TypeId {
        TypeId::of::<DeterministicRandom>()
    }
}

impl JSONHelper for DeterministicRandom {
    fn get_type_name(&self) -> &'static str {
        "DeterministicRandom"
    }

    fn serialize_json(&self) -> Result<serde_json::Value, anyhow::Error> {
        bail!("not supported")
    }

    fn is_supported(&self) -> bool {
        false
    }
}

impl DynEq for DeterministicRandom {
    fn as_eq(&self) -> &dyn DynEq {
        self
    }

    fn is_equal(&self, _: &dyn DynEq) -> bool {
        false
    }
}

impl DynHash for DeterministicRandom {
    fn dyn_hash(&self, _: &mut dyn Hasher) {}
}


pub fn random_fn(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &ChainState = context.get().context("chain state not found")?;
    Ok(Some(Value::Opaque(OpaqueWrapper::new(state.random.clone())).into()))
}

pub fn random_u8(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let random: &mut DeterministicRandom = opaque.as_mut()?;

    let mut buffer = [0; 1];
    random.fill(&mut buffer).context("filling random buffer")?;

    let value = buffer[0];

    Ok(Some(Value::U8(value).into()))
}

pub fn random_u16(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let random: &mut DeterministicRandom = opaque.as_mut()?;

    let mut buffer = [0; 2];
    random.fill(&mut buffer).context("filling random buffer")?;

    let value = u16::from_le_bytes(buffer);

    Ok(Some(Value::U16(value).into()))
}

pub fn random_u32(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let random: &mut DeterministicRandom = opaque.as_mut()?;

    let mut buffer = [0; 4];
    random.fill(&mut buffer).context("filling random buffer")?;

    let value = u32::from_le_bytes(buffer);

    Ok(Some(Value::U32(value).into()))
}

pub fn random_u64(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let random: &mut DeterministicRandom = opaque.as_mut()?;

    let mut buffer = [0; 8];
    random.fill(&mut buffer).context("filling random buffer")?;

    let value = u64::from_le_bytes(buffer);

    Ok(Some(Value::U64(value).into()))
}

pub fn random_u128(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let random: &mut DeterministicRandom = opaque.as_mut()?;

    let mut buffer = [0; 16];
    random.fill(&mut buffer).context("filling random buffer")?;

    let value = u128::from_le_bytes(buffer);

    Ok(Some(Value::U128(value).into()))
}

pub fn random_u256(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let random: &mut DeterministicRandom = opaque.as_mut()?;

    let mut buffer = [0; 32];
    random.fill(&mut buffer).context("filling random buffer")?;

    let value = U256::from_le_bytes(buffer);
    Ok(Some(Value::U256(value).into()))
}

pub fn random_bool(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque_mut()?;
    let random: &mut DeterministicRandom = opaque.as_mut()?;

    let mut buffer = [0; 1];
    random.fill(&mut buffer).context("filling random buffer")?;

    let value = buffer[0] & 1 == 1;

    Ok(Some(Value::Boolean(value).into()))
}