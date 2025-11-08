use std::hash::Hasher;

use xelis_vm::{
    impl_opaque,
    traits::{DynEq, DynHash, Serializable},
    Context,
    EnvironmentError,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult
};
use crate::{
    account::CiphertextCache,
    contract::{
        opaque::COMMITMENT_EQUALITY_PROOF_OPAQUE_ID,
        ContractMetadata,
        ModuleMetadata,
        OpaqueRistrettoPoint,
        OpaqueTranscript
    },
    crypto::{
        elgamal::{PedersenCommitment, PublicKey},
        proofs::CommitmentEqProof
    },
    serializer::*
};

impl_opaque!("CommitmentEqualityProof", CommitmentEqProof, json);
impl_opaque!("CommitmentEqualityProof", CommitmentEqProof);

impl DynEq for CommitmentEqProof {
    fn is_equal(&self, _: &dyn DynEq) -> bool {
        false
    }

    fn as_eq(&self) -> &dyn DynEq {
        self
    }
}

impl DynHash for CommitmentEqProof {
    fn dyn_hash(&self, _: &mut dyn Hasher) {}
}

impl Serializable for CommitmentEqProof {
    fn get_size(&self) -> usize {
        self.size()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(COMMITMENT_EQUALITY_PROOF_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }
}

pub fn commitment_eq_proof_verify(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut Context) -> FnReturnType<ContractMetadata> {
    let source_pubkey = PublicKey::from_point(
        params[0]
            .as_mut()
            .as_opaque_type_mut::<OpaqueRistrettoPoint>()?
            .decompressed()?
            .clone()
    );
    let ciphertext = params[1]
        .as_mut()
        .as_opaque_type_mut::<CiphertextCache>()?
        .decompressed()
        .map_err(|e| EnvironmentError::Any(e.into()))?
        .clone();
    let commitment = PedersenCommitment::from_point(
        params[2]
            .as_mut()
            .as_opaque_type_mut::<OpaqueRistrettoPoint>()?
            .decompressed()?
            .clone()
    );
    let transcript: &mut OpaqueTranscript = params[3]
        .as_mut()
        .as_opaque_type_mut()?;

    let zelf = zelf?;
    let zelf: &CommitmentEqProof = zelf.as_opaque_type()?;
    let valid = zelf.verify(&source_pubkey, &ciphertext, &commitment, &mut transcript.0)
        .is_ok();

    Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
}
