use matriochka::OptionExt;
use std::sync::Arc;
use xelis_vm::{
    RuntimeValue,
    Heap,
    PrimitiveInteger,
    Opaque,
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
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

#[derive(Clone, Debug, Opaque)]
#[opaque(hash, eq)]
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

pub fn transaction(_: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, _heap: &mut Heap) -> FnReturnType<ContractMetadata> {
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

pub fn transaction_nonce(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U64(tx.inner.get_nonce())).into()))
    })
}

pub fn transaction_hash(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(RuntimeValue::Opaque(tx.hash.clone().into()).into()))
    })
}

pub fn transaction_source(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
        let state = state_from_context(context)?;

        let address = tx.inner.get_source()
            .as_address(state.mainnet);

        Ok(SysCallResult::Return(RuntimeValue::Opaque(address.into()).into()))
    })
}

pub fn transaction_fee(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U64(tx.inner.get_fee())).into()))
    })
}

pub fn transaction_signature(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let tx: &OpaqueTransaction = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(RuntimeValue::Opaque(tx.inner.get_signature().clone().into()).into()))
    })
}