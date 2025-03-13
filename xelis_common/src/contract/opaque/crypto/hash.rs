use anyhow::Context as AnyhowContext;
use sha3::{Digest, Sha3_256};
use xelis_vm::{
    traits::Serializable,
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    OpaqueWrapper,
    Primitive,
    ValueCell,
    ValueError
};
use crate::{
    contract::HASH_OPAQUE_ID,
    crypto::{hash, Hash, HASH_SIZE},
    serializer::{Serializer, Writer}
};

impl Serializable for Hash {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(HASH_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }
}

pub fn hash_as_bytes_fn(_: FnInstance, _: FnParams, context: &mut Context) -> FnReturnType {
    let hash: &Hash = context.get().context("hash not found")?;
    let bytes = hash.as_bytes().into_iter().map(|b| Primitive::U8(*b).into()).collect();
    Ok(Some(ValueCell::Array(bytes)))
}

pub fn hash_from_bytes_fn(_: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let param = params.remove(0)
        .into_owned()?;
    let values = param.as_vec()?;

    if values.len() != HASH_SIZE {
        return Err(EnvironmentError::InvalidParameter);
    }

    let mut bytes = Vec::with_capacity(HASH_SIZE);
    for value in values {
        let byte = value.as_u8()?;
        bytes.push(byte);
    }

    let hash = Hash::from_bytes(&bytes)
        .context("failed to create hash from bytes")?;

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(hash)).into()))
}

pub fn hash_from_hex_fn(_: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let param = params.remove(0)
        .into_owned()?;
    let hex = param.as_string()?;

    if hex.len() != HASH_SIZE * 2 {
        return Err(EnvironmentError::InvalidParameter);
    }

    let hash = Hash::from_hex(hex)
        .context("failed to create hash from hex")?;

    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(hash)).into()))
}

pub fn blake3_fn(_: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let input = params.remove(0)
        .into_owned()?
        .as_vec()?
        .iter()
        .map(|v| v.as_u8())
        .collect::<Result<Vec<u8>, ValueError>>()?;

    let hash = hash(&input);
    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(hash)).into()))
}

pub fn sha256_fn(_: FnInstance, mut params: FnParams, _: &mut Context) -> FnReturnType {
    let input = params.remove(0)
        .into_owned()?
        .as_vec()?
        .into_iter()
        .map(|v| v.as_u8())
        .collect::<Result<Vec<u8>, ValueError>>()?;

    let hash = Hash::new(Sha3_256::digest(&input).into());
    Ok(Some(Primitive::Opaque(OpaqueWrapper::new(hash)).into()))
}
