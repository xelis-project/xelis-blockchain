use core::hash;

use anyhow::Context as _;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use xelis_vm::{
    impl_opaque,
    traits::Serializable,
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    SysCallResult,
    ValueCell
};

use crate::{
    contract::{ModuleMetadata, OpaqueScalar, RISTRETTO_OPAQUE_ID},
    crypto::{elgamal::RISTRETTO_COMPRESSED_SIZE, proofs::G},
    serializer::{Serializer as _, Writer},
};

impl_opaque!("RistrettoPoint", OpaqueRistrettoPoint, json);
impl_opaque!("RistrettoPoint", OpaqueRistrettoPoint);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpaqueRistrettoPoint {
    /// Compressed representation of a Ristretto point
    Compressed(CompressedRistretto),
    /// Decompressed representation of a Ristretto point
    /// Contains both the compressed form and the decompressed point
    Decompressed(CompressedRistretto, RistrettoPoint),
}

impl hash::Hash for OpaqueRistrettoPoint {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        match self {
            OpaqueRistrettoPoint::Compressed(c) => c.hash(state),
            OpaqueRistrettoPoint::Decompressed(c, _) => c.hash(state),
        }
    }
}

impl OpaqueRistrettoPoint {
    pub fn is_compressed(&self) -> bool {
        matches!(self, OpaqueRistrettoPoint::Compressed(_))
    }

    pub fn is_decompressed(&self) -> bool {
        matches!(self, OpaqueRistrettoPoint::Decompressed(_, _))
    }

    pub fn compressed(&self) -> &CompressedRistretto {
        match self {
            OpaqueRistrettoPoint::Compressed(c) => c,
            OpaqueRistrettoPoint::Decompressed(c, _) => c,
        }
    }

    pub fn computable(&mut self) -> Option<&mut RistrettoPoint> {
        match self {
            OpaqueRistrettoPoint::Compressed(c) => {
                let decompressed = c.decompress()?;
                *self = OpaqueRistrettoPoint::Decompressed(
                    c.clone(),
                    decompressed,
                );

                let OpaqueRistrettoPoint::Decompressed(_, point) = self else {
                    unreachable!();
                };

                Some(point)
            }
            OpaqueRistrettoPoint::Decompressed(_, point) => Some(point),
        }
    }

    pub fn into_point(self) -> Result<RistrettoPoint, EnvironmentError> {
        match self {
            OpaqueRistrettoPoint::Compressed(c) => c.decompress()
                .ok_or(EnvironmentError::Static("Failed to decompress Ristretto point")),
            OpaqueRistrettoPoint::Decompressed(_, point) => Ok(point),
        }
    }
}

impl Serialize for OpaqueRistrettoPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.compressed().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OpaqueRistrettoPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let c = CompressedRistretto::deserialize(deserializer)?;
        Ok(OpaqueRistrettoPoint::Compressed(c))
    }
}

impl Serializable for OpaqueRistrettoPoint {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(RISTRETTO_OPAQUE_ID);
        self.compressed().write(&mut writer);
        writer.total_write()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn get_size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE
    }
}

pub fn ristretto_add_scalar(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let scalar: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    let computable = zelf.computable()
        .context("Ciphertext not computable")?;

    *computable += scalar.0 * (*G);

    Ok(SysCallResult::None)
}

pub fn ristretto_sub_scalar(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let scalar: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    let computable = zelf.computable()
        .context("Ciphertext not computable")?;

    *computable -= scalar.0 * (*G);

    Ok(SysCallResult::None)
}

pub fn ristretto_add(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let point: OpaqueRistrettoPoint = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let computable = zelf.computable()
        .context("left point not computable")?;

    *computable += point.into_point()?;

    Ok(SysCallResult::None)
}

pub fn ristretto_sub(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let point: OpaqueRistrettoPoint = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let computable = zelf.computable()
        .context("left point not computable")?;

    *computable -= point.into_point()?;

    Ok(SysCallResult::None)
}

pub fn ristretto_mul_scalar(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let scalar: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    let computable = zelf.computable()
        .context("Ciphertext not computable")?;

    *computable *= scalar.0;

    Ok(SysCallResult::None)
}

pub fn ristretto_div_scalar(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let scalar: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    if scalar.0 == Scalar::ZERO {
        return Err(EnvironmentError::Static("Scalar cannot be zero for division"));
    }

    let computable = zelf.computable()
        .context("Ciphertext not computable")?;

    *computable *= scalar.0.invert();

    Ok(SysCallResult::None)
}

pub fn ristretto_from_bytes(_: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let bytes: &[u8] = params[0]
        .as_ref()
        .as_bytes()?;

    let compressed = CompressedRistretto::from_slice(bytes)
        .context("Invalid bytes length")?;
    let point = OpaqueRistrettoPoint::Compressed(compressed);

    Ok(SysCallResult::Return(point.into()))
}

pub fn ristretto_to_bytes(zelf: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &OpaqueRistrettoPoint = zelf?.as_opaque_type()?;
    let compressed = zelf.compressed();

    let bytes = compressed.as_bytes().to_vec();
    Ok(SysCallResult::Return(ValueCell::Bytes(bytes).into()))
}