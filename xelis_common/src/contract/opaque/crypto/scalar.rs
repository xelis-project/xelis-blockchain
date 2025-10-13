use anyhow::Context as _;
use curve25519_dalek::Scalar;
use serde::{Deserialize, Serialize};
use xelis_vm::{
    impl_opaque,
    traits::Serializable,
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
    ValueCell
};

use crate::{
    contract::{
        ModuleMetadata,
        OpaqueRistrettoPoint,
        SCALAR_OPAQUE_ID
    },
    crypto::{
        elgamal::SCALAR_SIZE,
        proofs::G
    },
    serializer::{Serializer, Writer}
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpaqueScalar(pub Scalar);

impl_opaque!("Scalar", OpaqueScalar, json);
impl_opaque!("Scalar", OpaqueScalar);

impl Serializable for OpaqueScalar {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(SCALAR_OPAQUE_ID);
        self.0.write(&mut writer);
        writer.total_write()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn get_size(&self) -> usize {
        SCALAR_SIZE
    }
}

pub fn scalar_from_u64(_: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let value = params[0]
        .as_u64()?;

    let scalar = Scalar::from(value);
    Ok(SysCallResult::Return(OpaqueScalar(scalar).into()))
}

pub fn scalar_invert(zelf: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &OpaqueScalar = zelf.as_opaque_type()?;

    if zelf.0 == Scalar::ZERO {
        return Err(EnvironmentError::Static("Division by zero"));
    }

    let inverted = zelf.0.invert();
    Ok(SysCallResult::Return(OpaqueScalar(inverted).into()))
}

pub fn scalar_is_zero(zelf: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &OpaqueScalar = zelf.as_opaque_type()?;
    let is_zero = zelf.0 == Scalar::ZERO;

    Ok(SysCallResult::Return(Primitive::Boolean(is_zero).into()))
}

pub fn scalar_mul_base(zelf: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &OpaqueScalar = zelf.as_opaque_type()?;

    let point = zelf.0 * (*G);

    Ok(SysCallResult::Return(OpaqueRistrettoPoint::Decompressed(
        None,
        point,
    ).into()))
}

pub fn scalar_add(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &OpaqueScalar = zelf.as_opaque_type()?;
    let other: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    let result = zelf.0 + other.0;
    Ok(SysCallResult::Return(OpaqueScalar(result).into()))
}

pub fn scalar_sub(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &OpaqueScalar = zelf.as_opaque_type()?;
    let other: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    let result = zelf.0 - other.0;
    Ok(SysCallResult::Return(OpaqueScalar(result).into()))
}

pub fn scalar_mul(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &OpaqueScalar = zelf.as_opaque_type()?;
    let other: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    let result = zelf.0 * other.0;
    Ok(SysCallResult::Return(OpaqueScalar(result).into()))
}

pub fn scalar_div(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &OpaqueScalar = zelf.as_opaque_type()?;
    let other: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    if other.0 == Scalar::ZERO {
        return Err(EnvironmentError::Static("Division by zero"));
    }

    let result = zelf.0 * other.0.invert();
    Ok(SysCallResult::Return(OpaqueScalar(result).into()))
}

pub fn scalar_from_bytes(_: FnInstance, mut params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let bytes: [u8; SCALAR_SIZE] = ValueCell::to_bytes(&mut params.remove(0).into_owned())?
        .try_into()
        .ok()
        .context("Expected a byte array of length 32")?;

    let scalar = Scalar::from_canonical_bytes(bytes)
        .into_option()
        .map(|scalar| OpaqueScalar(scalar).into())
        .unwrap_or_default();

    Ok(SysCallResult::Return(scalar))
}

pub fn scalar_to_bytes(zelf: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &OpaqueScalar = zelf.as_opaque_type()?;
    let bytes = zelf.0.to_bytes().to_vec();

    Ok(SysCallResult::Return(ValueCell::Bytes(bytes).into()))
}