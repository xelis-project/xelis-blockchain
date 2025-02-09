use anyhow::Context as AnyhowContext;
use xelis_vm::{traits::{JSONHelper, Serializable}, Context, FnInstance, FnParams, FnReturnType, OpaqueWrapper, Value};
use crate::{contract::ChainState, transaction::Transaction};

use super::OpaqueSignature;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpaqueTransaction;

impl JSONHelper for OpaqueTransaction {}

impl Serializable for OpaqueTransaction {}

pub fn transaction(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Value::Opaque(OpaqueWrapper::new(OpaqueTransaction)).into()))
}

pub fn transaction_nonce(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let tx: &Transaction = context.get().context("current transaction not found")?;

    Ok(Some(Value::U64(tx.get_nonce()).into()))
}

pub fn transaction_hash(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get().context("chain state not found")?;

    Ok(Some(Value::Opaque(OpaqueWrapper::new(state.tx_hash.clone())).into()))
}

pub fn transaction_source(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let tx: &Transaction = context.get().context("current transaction not found")?;
    let state: &ChainState = context.get().context("chain state not found")?;

    let address = tx.get_source()
        .as_address(state.mainnet);

    Ok(Some(Value::Opaque(OpaqueWrapper::new(address)).into()))
}

pub fn transaction_fee(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let tx: &Transaction = context.get().context("current transaction not found")?;

    Ok(Some(Value::U64(tx.get_fee()).into()))
}

pub fn transaction_signature(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let tx: &Transaction = context.get().context("current transaction not found")?;

    Ok(Some(Value::Opaque(OpaqueWrapper::new(OpaqueSignature(tx.get_signature().clone()))).into()))
}