use std::{any::TypeId, fmt, hash::{Hash, Hasher}, ops::Deref};

use anyhow::Context as AnyhowContext;
use serde::{Deserialize, Serialize};
use xelis_vm::{traits::Serializable, Context, FnInstance, FnParams, FnReturnType, Opaque, OpaqueWrapper, Value};
use crate::{api::RPCTransaction, contract::ChainState, crypto, immutable::Immutable, transaction::Transaction};

#[derive(Clone, Debug)]
pub struct OpaqueTransaction {
    hash: crypto::Hash,
    transaction: Immutable<Transaction>,
    mainnet: bool,
}

impl OpaqueTransaction {
    pub fn new(hash: crypto::Hash, transaction: Immutable<Transaction>, mainnet: bool) -> Self {
        Self {
            hash,
            transaction,
            mainnet,
        }
    }

    pub fn get_hash(&self) -> &crypto::Hash {
        &self.hash
    }
}

impl Serialize for OpaqueTransaction {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let rpc = RPCTransaction::from_tx(&self.transaction, &self.hash, self.mainnet);
        rpc.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for OpaqueTransaction {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let rpc = RPCTransaction::deserialize(deserializer)?;
        let is_mainnet = rpc.source.is_mainnet();
        let hash = rpc.hash.to_owned();
        let transaction = Transaction::from(rpc);

        Ok(Self::new(hash.into_owned(), Immutable::Owned(transaction), is_mainnet))
    }
}


impl Serializable for OpaqueTransaction {
    fn is_serializable(&self) -> bool {
        false
    }
}

impl AsRef<Transaction> for OpaqueTransaction {
    fn as_ref(&self) -> &Transaction {
        &self.transaction
    }
}

impl Hash for OpaqueTransaction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for OpaqueTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for OpaqueTransaction {}

impl Deref for OpaqueTransaction {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl Opaque for OpaqueTransaction {
    fn get_type(&self) -> TypeId {
        TypeId::of::<Transaction>()
    }

    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }

    fn display(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transaction")
    }
}

pub fn current_transaction(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let tx: &OpaqueTransaction = context.get().context("current transaction not found")?;
    Ok(Some(Value::Opaque(OpaqueWrapper::new(tx.clone())).into()))
}

pub fn transaction_nonce(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque()?;
    let tx: &OpaqueTransaction = opaque.as_ref()?;
    Ok(Some(Value::U64(tx.get_nonce()).into()))
}

pub fn transaction_hash(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque()?;
    let tx: &OpaqueTransaction = opaque.as_ref()?;
    Ok(Some(Value::Opaque(OpaqueWrapper::new(tx.get_hash().clone())).into()))
}

pub fn transaction_source(zelf: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let state: &ChainState = context.get().context("chain state not found")?;
    let opaque = zelf?.as_opaque()?;
    let tx: &OpaqueTransaction = opaque.as_ref()?;
    let address = tx.get_source()
        .as_address(state.mainnet);

    Ok(Some(Value::Opaque(OpaqueWrapper::new(address)).into()))
}

pub fn transaction_fee(zelf: FnInstance, _: FnParams, _: &mut Context) -> FnReturnType {
    let opaque = zelf?.as_opaque()?;
    let tx: &OpaqueTransaction = opaque.as_ref()?;
    Ok(Some(Value::U64(tx.get_fee()).into()))
}