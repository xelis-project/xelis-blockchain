use std::any::TypeId;
use anyhow::Context as AnyhowContext;
use xelis_builder::ConstFnParams;
use xelis_vm::{traits::Serializable, Constant, Context, FnInstance, FnParams, FnReturnType, Opaque, OpaqueWrapper, Value, ValueCell};
use crate::crypto::Hash;

use super::{Serializer, Writer, HASH_OPAQUE_ID};

impl Serializable for Hash {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(HASH_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }
}

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

pub fn hash_from_bytes_fn(params: ConstFnParams) -> Result<Constant, anyhow::Error> {
    let values = params[0].as_vec()?;
    let mut bytes = Vec::with_capacity(values.len());
    for value in values {
        let byte = value.as_u8()?;
        bytes.push(byte);
    }

    let hash = Hash::from_bytes(&bytes)
        .context("failed to create hash from bytes")?;

    Ok(Constant::Default(Value::Opaque(OpaqueWrapper::new(hash))))
}

pub fn hash_from_hex_fn(params: ConstFnParams) -> Result<Constant, anyhow::Error> {
    let hex = params[0].as_string()?;
    let hash = Hash::from_hex(hex)
        .context("failed to create hash from hexadecimal")?;

    Ok(Constant::Default(Value::Opaque(OpaqueWrapper::new(hash))))
}