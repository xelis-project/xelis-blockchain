use anyhow::Context as AnyhowContext;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive
};
use crate::{contract::ChainState, transaction::Transaction};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpaqueTransaction;

impl JSONHelper for OpaqueTransaction {}

impl Serializable for OpaqueTransaction {}

pub fn transaction(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(OpaqueTransaction)).into()))
}

pub fn transaction_nonce(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let tx: &Transaction = context.get().context("current transaction not found")?;

    Ok(Some(Primitive::U64(tx.get_nonce()).into()))
}

pub fn transaction_hash(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &ChainState = context.get().context("chain state not found")?;

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(state.tx_hash.clone())).into()))
}

pub fn transaction_source(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let tx: &Transaction = context.get().context("current transaction not found")?;
    let state: &ChainState = context.get().context("chain state not found")?;

    let address = tx.get_source()
        .as_address(state.mainnet);

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(address)).into()))
}

pub fn transaction_fee(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let tx: &Transaction = context.get().context("current transaction not found")?;

    Ok(Some(Primitive::U64(tx.get_fee()).into()))
}

pub fn transaction_signature(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let tx: &Transaction = context.get().context("current transaction not found")?;

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(tx.get_signature().clone())).into()))
}