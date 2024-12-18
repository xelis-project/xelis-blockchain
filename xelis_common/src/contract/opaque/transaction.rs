use std::{any::TypeId, fmt};

use anyhow::{bail, Context as AnyhowContext};
use xelis_vm::{traits::{JSONHelper, Serializable}, Context, FnInstance, FnParams, FnReturnType, Opaque, OpaqueWrapper, Value};
use crate::{contract::ChainState, transaction::Transaction};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpaqueTransaction;

impl JSONHelper for OpaqueTransaction {
    fn get_type_name(&self) -> &'static str {
        "Transaction"
    }

    fn serialize_json(&self) -> Result<serde_json::Value, anyhow::Error> {
        bail!("Transaction is not serializable")
    }

    fn is_json_supported(&self) -> bool {
        false
    }
}

impl Serializable for OpaqueTransaction {
    fn is_serializable(&self) -> bool {
        false
    }
}

impl Opaque for OpaqueTransaction {
    fn get_type(&self) -> TypeId {
        TypeId::of::<OpaqueTransaction>()
    }

    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }

    fn display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transaction")
    }
}

pub fn transaction(_: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    Ok(Some(Value::Opaque(OpaqueWrapper::new(OpaqueTransaction)).into()))
}

pub fn transaction_nonce(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let tx: &Transaction = context.get().context("current transaction not found not found")?;

    Ok(Some(Value::U64(tx.get_nonce()).into()))
}

pub fn transaction_hash(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let state: &ChainState = context.get().context("chain state not found")?;

    Ok(Some(Value::Opaque(OpaqueWrapper::new(state.tx_hash.clone())).into()))
}

pub fn transaction_source(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let tx: &Transaction = context.get().context("current transaction not found not found")?;
    let state: &ChainState = context.get().context("chain state not found")?;

    let address = tx.get_source()
        .as_address(state.mainnet);

    Ok(Some(Value::Opaque(OpaqueWrapper::new(address)).into()))
}

pub fn transaction_fee(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let _: &OpaqueTransaction = zelf?.as_opaque_type()?;
    let tx: &Transaction = context.get().context("current transaction not found not found")?;

    Ok(Some(Value::U64(tx.get_fee()).into()))
}