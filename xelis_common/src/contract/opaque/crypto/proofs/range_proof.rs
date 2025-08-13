use std::hash::Hasher;

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
        ModuleMetadata,
        OpaqueRistrettoPoint,
        OpaqueTranscript
    },
    crypto::proofs::{BP_GENS, BULLET_PROOF_SIZE, PC_GENS},
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

pub fn range_proof_verify(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let commitments = params[0]
        .as_mut()
        .as_mut_vec()?
        .iter_mut()
        .map(|p| {
            let opaque: &mut OpaqueRistrettoPoint = p.as_mut()
                .as_opaque_type_mut()?;
            let (compressed, point) = opaque.both()?;
            Ok((point.clone(), compressed.clone()))
        })
        .collect::<Result<Vec<_>, EnvironmentError>>()?;

    let transcript: &mut OpaqueTranscript = params[1]
        .as_mut()
        .as_opaque_type_mut()?;

    let zelf: &RangeProofWrapper = zelf?.as_opaque_type()?;
    let valid = zelf.0.verify_multiple(&BP_GENS, &PC_GENS, &mut transcript.0, &commitments, BULLET_PROOF_SIZE)
        .is_ok();

    Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
}