use anyhow::Context as AnyhowContext;
use std::sync::Arc;
use xelis_vm::{
    traits::{JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    SysCallResult
};
use crate::{
    contract::{
        vm::ContractCaller,
        ChainState,
        ContractMetadata,
        ModuleMetadata,
        state_from_context,
    },
    crypto::Hash,
    transaction::Transaction
};

#[derive(Clone, Debug)]
pub struct OpaqueTransaction {
    pub hash: Hash,
    pub inner: Arc<Transaction>
}

impl PartialEq for OpaqueTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash.eq(&other.hash)
    }
}

impl Eq for OpaqueTransaction {}

impl std::hash::Hash for OpaqueTransaction {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl JSONHelper for OpaqueTransaction {}

impl Serializable for OpaqueTransaction {}

pub fn transaction(_: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let state: &ChainState = context.get()
        .context("chain state not found")?;
    if let ContractCaller::Transaction(hash, tx) = &state.caller {
        return Ok(SysCallResult::Return(OpaqueTransaction {
            inner: (*tx).clone(),
            hash: (*hash).clone(),
        }.into()).into())
    }

    Ok(SysCallResult::Return(Primitive::Null.into()))
}

pub fn transaction_nonce(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::U64(tx.inner.get_nonce()).into()))
}

pub fn transaction_hash(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(tx.hash.clone())).into()))
}

pub fn transaction_source(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
    let state = state_from_context(context)?;

    let address = tx.inner.get_source()
        .as_address(state.mainnet);

    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(address)).into()))
}

pub fn transaction_fee(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::U64(tx.inner.get_fee()).into()))
}

pub fn transaction_signature(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::Opaque(OpaqueWrapper::new(tx.inner.get_signature().clone())).into()))
}