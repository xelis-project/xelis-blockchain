use core::fmt;
use std::hash::Hasher;

use anyhow::Context as _;
use merlin::Transcript;
use xelis_vm::{
    impl_opaque,
    traits::{DynEq, DynHash, JSONHelper, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    SysCallResult,
    ValueCell
};

use crate::{contract::{ModuleMetadata, OpaqueRistrettoPoint, OpaqueScalar}, crypto::ProtocolTranscript};

impl_opaque!("Transcript", OpaqueTranscript);

#[derive(Clone)]
pub struct OpaqueTranscript(pub Transcript);

impl fmt::Debug for OpaqueTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpaqueTranscript")
    }
}

impl DynEq for OpaqueTranscript {
    fn is_equal(&self, _: &dyn DynEq) -> bool {
        false
    }

    fn as_eq(&self) -> &dyn DynEq {
        self
    }
}

impl DynHash for OpaqueTranscript {
    fn dyn_hash(&self, _: &mut dyn Hasher) {
        // No hashing needed for OpaqueTranscript
    }
}

impl JSONHelper for OpaqueTranscript {
    fn is_json_supported(&self) -> bool {
        false
    }

    fn serialize_json(&self) -> Result<serde_json::Value, anyhow::Error> {
        Err(anyhow::anyhow!("OpaqueTranscript does not support JSON serialization"))
    }
}

impl Serializable for OpaqueTranscript {
    fn serialize(&self, _: &mut Vec<u8>) -> usize {
        0
    }

    fn is_serializable(&self) -> bool {
        false
    }

    fn get_size(&self) -> usize {
        32
    }
}

pub fn transcript_new(_: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let label = params[0]
        .as_ref()
        .as_bytes()?;

    let transcript = OpaqueTranscript(Transcript::new(&label));
    Ok(SysCallResult::Return(transcript.into()))
}

pub fn transcript_challenge_scalar(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

    let label = params[0]
        .as_ref()
        .as_bytes()?;

    let scalar = zelf.0.challenge_scalar(&label);
    Ok(SysCallResult::Return(OpaqueScalar(scalar).into()))
}

pub fn transcript_challenge_bytes(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, context: &mut Context) -> FnReturnType<ModuleMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

    let label = params[0]
        .as_ref()
        .as_bytes()?;

    let bytes_len = params[0]
        .as_ref()
        .as_u32()?;

    if bytes_len == 0 {
        return Err(anyhow::anyhow!("Bytes length must be greater than zero").into());
    }

    if bytes_len > 256 {
        return Err(anyhow::anyhow!("Bytes length must not exceed 256 bytes").into());
    }

    context.increase_gas_usage(bytes_len as u64 * 5)?;

    let mut buffer = vec![0u8; bytes_len as usize];
    zelf.0.challenge_bytes(&label, &mut buffer);

    Ok(SysCallResult::Return(ValueCell::Bytes(buffer).into()))
}

pub fn transcript_append_message(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

    let label = params[0]
        .as_ref()
        .as_bytes()?;

    let message = params[1]
        .as_ref()
        .as_bytes()?;

    zelf.0.append_message(&label, &message);

    Ok(SysCallResult::None)
}

pub fn transcript_append_point(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

    let label = params[0]
        .as_ref()
        .as_bytes()?;

    let point: &OpaqueRistrettoPoint = params[1]
        .as_ref()
        .as_opaque_type()?;

    zelf.0.append_point(&label, &point.compressed());

    Ok(SysCallResult::None)
}

pub fn transcript_validate_and_append_point(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

    let label = params[0]
        .as_ref()
        .as_bytes()?;

    let point: &OpaqueRistrettoPoint = params[1]
        .as_ref()
        .as_opaque_type()?;

    zelf.0.validate_and_append_point(&label, &point.compressed())
        .context("Failed to validate and append point to transcript")?;

    Ok(SysCallResult::None)
}

pub fn transcript_append_scalar(zelf: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let mut zelf = zelf?;
    let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

    let label = params[0]
        .as_ref()
        .as_bytes()?;

    let scalar: &OpaqueScalar = params[1]
        .as_ref()
        .as_opaque_type()?;

    zelf.0.append_scalar(&label, &scalar.0);

    Ok(SysCallResult::None)
}

