use core::fmt;

use matriochka::ResultExt;
use merlin::Transcript;
use xelis_vm::{
    RuntimeValue,
    Heap,
    Opaque,
    EnvironmentError,
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
    SysCallResult
};

use crate::{
    contract::{
        ContractMetadata,
        ModuleMetadata,
        OpaqueRistrettoPoint,
        OpaqueScalar
    },
    crypto::ProtocolTranscript,
};

#[derive(Clone, Opaque)]
#[opaque(name = "Transcript", size = 32)]
pub struct OpaqueTranscript(pub Transcript);

impl fmt::Debug for OpaqueTranscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpaqueTranscript")
    }
}

pub fn transcript_new(_: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let label = params[0]
        .as_ref(heap)
        .as_bytes()?;

    context.increase_gas_usage(label.len() as u64 * 2)?;

    let transcript = OpaqueTranscript(Transcript::new(&label));
    Ok(SysCallResult::Return(transcript.into()))
}

pub fn transcript_challenge_scalar(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

        let label = params[0]
            .as_ref(heap)
            .as_bytes()?;

        context.increase_gas_usage(label.len() as u64 * 2)?;

        let scalar = zelf.0.challenge_scalar(&label);
        Ok(SysCallResult::Return(OpaqueScalar(scalar).into()))
    })
}

pub fn transcript_challenge_bytes(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

        let label = params[0]
            .as_ref(heap)
            .as_bytes()?;

        let bytes_len = params[1]
            .as_ref(heap)
            .as_u32()?;

        if bytes_len == 0 {
            return Err(EnvironmentError::Static("Bytes length must be greater than zero"));
        }

        if bytes_len > 256 {
            return Err(EnvironmentError::Static("Bytes length must not exceed 256 bytes"));
        }

        context.increase_gas_usage(label.len() as u64 * 2)?;
        context.increase_gas_usage(bytes_len as u64 * 5)?;

        let mut buffer = vec![0u8; bytes_len as usize];
        zelf.0.challenge_bytes(&label, &mut buffer);

        Ok(SysCallResult::Return(RuntimeValue::Bytes(buffer).into()))
    })
}

pub fn transcript_append_message(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

        let label = params[0]
            .as_ref(heap)
            .as_bytes()?;

        let message = params[1]
            .as_ref(heap)
            .as_bytes()?;

        context.increase_gas_usage((label.len() + message.len()) as u64 * 2)?;

        zelf.0.append_message(&label, &message);

        Ok(SysCallResult::None)
    })
}

pub fn transcript_append_point(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

        let label = params[0]
            .as_ref(heap)
            .as_bytes()?;

        context.increase_gas_usage(label.len() as u64 * 2)?;

        let point: &OpaqueRistrettoPoint = params[1]
            .as_ref(heap)
            .as_opaque_type()?;

        zelf.0.append_point(&label, &point.compressed());

        Ok(SysCallResult::None)
    })
}

pub fn transcript_validate_and_append_point(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

        let label = params[0]
            .as_ref(heap)
            .as_bytes()?;

        context.increase_gas_usage(label.len() as u64 * 2)?;

        let point: &OpaqueRistrettoPoint = params[1]
            .as_ref(heap)
            .as_opaque_type()?;

        zelf.0.validate_and_append_point(&label, &point.compressed())
            .context("Failed to validate and append point to transcript")?;

        Ok(SysCallResult::None)
    })
}

pub fn transcript_append_scalar(zelf: FnInstance, params: FnParams<'_>, _: &ModuleMetadata<'_>, context: &mut VMContext, heap: &mut Heap) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    heap.with_value(zelf, |zelf, heap| {
        let zelf: &mut OpaqueTranscript = zelf.as_opaque_type_mut()?;

        let label = params[0]
            .as_ref(heap)
            .as_bytes()?;

        context.increase_gas_usage(label.len() as u64 * 2)?;

        let scalar: &OpaqueScalar = params[1]
            .as_ref(heap)
            .as_opaque_type()?;

        zelf.0.append_scalar(&label, &scalar.0);

        Ok(SysCallResult::None)
    })
}
