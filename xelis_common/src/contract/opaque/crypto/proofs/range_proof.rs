use std::hash::Hasher;

use anyhow::Context as _;
use bulletproofs::RangeProof;
use serde::{Deserialize, Serialize};
use xelis_vm::{
    impl_opaque,
    traits::{DynEq, DynHash, Serializable},
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult,
};
use crate::{
    contract::{
        opaque::RANGE_PROOF_OPAQUE_ID,
        ContractMetadata,
        ModuleMetadata,
        OpaqueRistrettoPoint,
        OpaqueTranscript
    },
    crypto::proofs::{BP_GENS, PC_GENS},
    serializer::*
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProofWrapper(pub RangeProof);

impl_opaque!("RangeProof", RangeProofWrapper, json);
impl_opaque!("RangeProof", RangeProofWrapper);

impl DynEq for RangeProofWrapper {
    fn is_equal(&self, _: &dyn DynEq) -> bool {
        false
    }

    fn as_eq(&self) -> &dyn DynEq {
        self
    }
}

impl DynHash for RangeProofWrapper {
    fn dyn_hash(&self, _: &mut dyn Hasher) {}
}

impl Serializable for RangeProofWrapper {
    fn get_size(&self) -> usize {
        self.0.size()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(RANGE_PROOF_OPAQUE_ID);
        self.0.write(&mut writer);
        writer.total_write()
    }
}

pub fn range_proof_verify_single(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {    
    let proof_size = params[2].as_ref()
        .as_u8()?;

    if proof_size == 0 || proof_size > 64 {
        return Err(EnvironmentError::Static("proof size must be between 1 and 64"));
    }

    let [left, right] = params.get_disjoint_mut([0, 1])
        .context("disjoint mut")?;

    let commitment = {
            let commitment: &mut OpaqueRistrettoPoint = left
                .as_mut()
                .as_opaque_type_mut()?;

            let (compressed, decompressed) = commitment.both()?;
            (decompressed.clone(), compressed.clone())
    };

    let transcript: &mut OpaqueTranscript = right
        .as_mut()
        .as_opaque_type_mut()?;

    let zelf = zelf?;
    let zelf: &RangeProofWrapper = zelf.as_opaque_type()?;

    let valid = zelf.0.verify_single(&BP_GENS, &PC_GENS, &mut transcript.0, &commitment, proof_size as _)
        .is_ok();

    Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
}

pub fn range_proof_verify_multiple(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, context: &mut Context) -> FnReturnType<ContractMetadata> {
    // SAFETY: no other reference is made to it
    let commitments = unsafe {
        params[0]
        .as_mut()
        .as_mut_vec()?
        .iter_mut()
        .map(|p| {
            let opaque: &mut OpaqueRistrettoPoint = p.as_mut()
                .as_opaque_type_mut()?;
            let (compressed, point) = opaque.both()?;
            Ok((point.clone(), compressed.clone()))
        })
        .collect::<Result<Vec<_>, EnvironmentError>>()?
    };

    context.increase_gas_usage((commitments.len() * 5000) as u64)?;

    let proof_size = params[2].as_ref()
        .as_u8()?;

    if proof_size == 0 || proof_size > 64 {
        return Err(EnvironmentError::Static("proof size must be between 1 and 64"));
    }

    let transcript: &mut OpaqueTranscript = params[1]
        .as_mut()
        .as_opaque_type_mut()?;

    let zelf = zelf?;
    let zelf: &RangeProofWrapper = zelf.as_opaque_type()?;

    let valid = zelf.0.verify_multiple(&BP_GENS, &PC_GENS, &mut transcript.0, &commitments, proof_size as _)
        .is_ok();

    Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
}