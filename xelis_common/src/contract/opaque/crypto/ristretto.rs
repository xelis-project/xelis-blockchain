use core::hash;
use std::borrow::Cow;

use anyhow::Context as _;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::{Identity, IsIdentity}, RistrettoPoint, Scalar};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
    Decompressed(Option<CompressedRistretto>, RistrettoPoint),
}

impl hash::Hash for OpaqueRistrettoPoint {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.compressed().hash(state);
    }
}

impl OpaqueRistrettoPoint {
    pub fn is_compressed(&self) -> bool {
        matches!(self, OpaqueRistrettoPoint::Compressed(_))
    }

    pub fn is_decompressed(&self) -> bool {
        matches!(self, OpaqueRistrettoPoint::Decompressed(_, _))
    }

    pub fn compressed<'a>(&'a self) -> Cow<'a, CompressedRistretto> {
        match self {
            OpaqueRistrettoPoint::Compressed(c) => Cow::Borrowed(c),
            OpaqueRistrettoPoint::Decompressed(c, point) => {
                if let Some(c) = c {
                    Cow::Borrowed(c)
                } else {
                    Cow::Owned(point.compress())
                }
            },
        }
    }

    pub fn is_identity(&self) -> bool {
        match self {
            OpaqueRistrettoPoint::Compressed(c) => c.is_identity(),
            OpaqueRistrettoPoint::Decompressed(_, point) => point.is_identity()
        }
    }

    fn decompress_internal(&mut self) -> Result<(), EnvironmentError> {
        match self {
            OpaqueRistrettoPoint::Compressed(c) => {
                let decompressed = c.decompress()
                    .ok_or(EnvironmentError::Static("Failed to decompress Ristretto point"))?;

                *self = OpaqueRistrettoPoint::Decompressed(Some(c.clone()), decompressed);
                Ok(())
            }
            OpaqueRistrettoPoint::Decompressed(_, _) => Ok(()),
        }
    }

    pub fn computable(&mut self) -> Result<&mut RistrettoPoint, EnvironmentError> {
        self.decompress_internal()?;

         let OpaqueRistrettoPoint::Decompressed(compressed, point) = self else {
            unreachable!();
        };

        // clear its cache
        *compressed = None;

        Ok(point)
    }

    pub fn decompressed(&mut self) -> Result<&RistrettoPoint, EnvironmentError> {
        self.decompress_internal()?;

        let OpaqueRistrettoPoint::Decompressed(_, point) = self else {
            unreachable!();
        };

        Ok(point)
    }

    pub fn both(&mut self) -> Result<(&CompressedRistretto, &RistrettoPoint), EnvironmentError> {
        self.decompress_internal()?;

        let OpaqueRistrettoPoint::Decompressed(compressed, point) = self else {
            unreachable!();
        };

        if compressed.is_none() {
            *compressed = Some(point.compress());
        }

        let compressed = compressed.as_ref()
            .ok_or(EnvironmentError::Static("Compressed point is not available"))?;

        Ok((compressed, point))
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

pub fn ristretto_is_identity(zelf: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &OpaqueRistrettoPoint = zelf?.as_opaque_type()?;
    Ok(SysCallResult::Return(Primitive::Boolean(zelf.is_identity()).into()))
}

pub fn ristretto_identity(_: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let point = OpaqueRistrettoPoint::Compressed(CompressedRistretto::identity());
    Ok(SysCallResult::Return(point.into()))
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

    let computable = zelf.computable()?;

    *computable -= scalar.0 * (*G);

    Ok(SysCallResult::None)
}

pub fn ristretto_add(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let point: OpaqueRistrettoPoint = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let computable = zelf.computable()?;

    *computable += point.into_point()?;

    Ok(SysCallResult::None)
}

pub fn ristretto_sub(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let point: OpaqueRistrettoPoint = params.remove(0)
        .into_owned()
        .into_opaque_type()?;

    let computable = zelf.computable()?;

    *computable -= point.into_point()?;

    Ok(SysCallResult::None)
}

pub fn ristretto_mul_scalar(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf: &mut OpaqueRistrettoPoint = zelf?.as_opaque_type_mut()?;
    let scalar: &OpaqueScalar = params[0]
        .as_ref()
        .as_opaque_type()?;

    let computable = zelf.computable()?;

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

    let computable = zelf.computable()?;

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