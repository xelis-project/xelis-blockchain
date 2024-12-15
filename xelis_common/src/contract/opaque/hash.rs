use std::any::TypeId;
use anyhow::Context as AnyhowContext;
use xelis_vm::{Context, FnInstance, FnParams, FnReturnType, Opaque, Value, ValueCell};
use crate::crypto::Hash;

impl Opaque for Hash {
    fn get_type(&self) -> TypeId {
        TypeId::of::<Hash>()
    }

    fn display(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hash({})", self)
    }

    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }
}

pub fn hash_as_bytes_fn(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let hash: &Hash = context.get().context("hash not found")?;
    let bytes = hash.as_bytes().into_iter().map(|b| Value::U8(*b).into()).collect();
    Ok(Some(ValueCell::Array(bytes)))
}