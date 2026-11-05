use core::hash;
use std::borrow::Cow;

use matriochka::ResultExt;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::{Identity, IsIdentity}, RistrettoPoint, Scalar};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use xelis_vm::{
    RuntimeValue,
    Heap,
    Opaque,
    traits::DynSerializable,
    VMContext,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult
};

use crate::{
    contract::{ModuleMetadata, ContractMetadata, OpaqueScalar, RISTRETTO_OPAQUE_ID},
    crypto::{elgamal::RISTRETTO_COMPRESSED_SIZE, proofs::G},
    serializer::{
        Error as SerializationError,
        Serializer as BinarySerializer,
        Writer
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Opaque)]
#[opaque(name = "RistrettoPoint", json, serializable, hash, eq)]
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

        let compressed = match compressed {
            Some(ct) => ct,
            None => compressed.insert(point.compress()),
        };

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

impl DynSerializable for OpaqueRistrettoPoint {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        RISTRETTO_OPAQUE_ID.write(&mut writer)?;
        self.compressed().write(&mut writer)?;
        Ok(buffer.len() - start)
    }

    fn get_size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE
    }
}

pub fn ristretto_is_identity(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let zelf: &OpaqueRistrettoPoint = zelf.as_opaque_type()?;
        Ok(SysCallResult::Return(Primitive::Boolean(zelf.is_identity()).into()))
    })
}

pub fn ristretto_identity(_: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, _heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let point = OpaqueRistrettoPoint::Compressed(CompressedRistretto::identity());
    Ok(SysCallResult::Return(point.into()))
}

pub fn ristretto_add_scalar(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let opaque: &mut OpaqueRistrettoPoint = zelf.as_opaque_type_mut()?;
        let scalar: &OpaqueScalar = params[0]
            .as_ref(heap)
            .as_opaque_type()?;

        let computable = opaque.computable()
            .context("Ciphertext not computable")?;

        *computable += scalar.0 * (*G);

        Ok::<(), EnvironmentError>(())
    })?;
    Ok(SysCallResult::Return(zelf.reference(heap)))
}

pub fn ristretto_sub_scalar(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let opaque: &mut OpaqueRistrettoPoint = zelf.as_opaque_type_mut()?;
        let scalar: &OpaqueScalar = params[0]
            .as_ref(heap)
            .as_opaque_type()?;

        let computable = opaque.computable()?;

        *computable -= scalar.0 * (*G);

        Ok::<(), EnvironmentError>(())
    })?;
    Ok(SysCallResult::Return(zelf.reference(heap)))
}

pub fn ristretto_add(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let opaque: &mut OpaqueRistrettoPoint = zelf.as_opaque_type_mut()?;
        let point: OpaqueRistrettoPoint = params.remove(0).into_owned(heap)?
            .into_opaque_type()?;

        let computable = opaque.computable()?;

        *computable += point.into_point()?;

        Ok::<(), EnvironmentError>(())
    })?;
    Ok(SysCallResult::Return(zelf.reference(heap)))
}

pub fn ristretto_sub(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let opaque: &mut OpaqueRistrettoPoint = zelf.as_opaque_type_mut()?;
        let point: OpaqueRistrettoPoint = params.remove(0).into_owned(heap)?
            .into_opaque_type()?;

        let computable = opaque.computable()?;

        *computable -= point.into_point()?;

        Ok::<(), EnvironmentError>(())
    })?;
    Ok(SysCallResult::Return(zelf.reference(heap)))
}

pub fn ristretto_mul_scalar(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let opaque: &mut OpaqueRistrettoPoint = zelf.as_opaque_type_mut()?;
        let scalar: &OpaqueScalar = params[0]
            .as_ref(heap)
            .as_opaque_type()?;

        let computable = opaque.computable()?;

        *computable *= scalar.0;

        Ok::<(), EnvironmentError>(())
    })?;
    Ok(SysCallResult::Return(zelf.reference(heap)))
}

pub fn ristretto_div_scalar(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let opaque: &mut OpaqueRistrettoPoint = zelf.as_opaque_type_mut()?;
        let scalar: &OpaqueScalar = params[0]
            .as_ref(heap)
            .as_opaque_type()?;

        if scalar.0 == Scalar::ZERO {
            return Err(EnvironmentError::Static("Scalar cannot be zero for division"));
        }

        let computable = opaque.computable()?;

        *computable *= scalar.0.invert();

        Ok::<(), EnvironmentError>(())
    })?;
    Ok(SysCallResult::Return(zelf.reference(heap)))
}

pub fn ristretto_from_bytes(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let bytes: &[u8] = params[0]
        .as_ref(heap)
        .as_bytes()?;

    let compressed = CompressedRistretto::from_slice(bytes)
        .context("Invalid bytes length")?;
    let point = OpaqueRistrettoPoint::Compressed(compressed);

    Ok(SysCallResult::Return(point.into()))
}

pub fn ristretto_to_bytes(zelf: FnInstance, _: FnParams<'_>, _: &ModuleMetadata<'_>, _: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, _heap| {
        let zelf: &OpaqueRistrettoPoint = zelf.as_opaque_type()?;
        let compressed = zelf.compressed();

        let bytes = compressed.as_bytes().to_vec();
        Ok(SysCallResult::Return(RuntimeValue::Bytes(bytes).into()))
    })
}