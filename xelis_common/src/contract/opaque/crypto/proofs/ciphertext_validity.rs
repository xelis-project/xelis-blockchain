use std::hash::Hasher;

use xelis_vm::{
    impl_opaque,
    traits::{DynEq, DynHash, Serializable},
    Context,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult
};
use crate::{
    contract::{opaque::CIPHERTEXT_VALIDITY_PROOF_OPAQUE_ID, ModuleMetadata, OpaqueRistrettoPoint, OpaqueTranscript},
    crypto::{elgamal::{DecryptHandle, PedersenCommitment, PublicKey}, proofs::CiphertextValidityProof},
    serializer::*
};

impl_opaque!("CiphertextValidityProof", CiphertextValidityProof, json);
impl_opaque!("CiphertextValidityProof", CiphertextValidityProof);

impl DynEq for CiphertextValidityProof {
    fn is_equal(&self, _: &dyn DynEq) -> bool {
        false
    }

    fn as_eq(&self) -> &dyn DynEq {
        self
    }
}

impl DynHash for CiphertextValidityProof {
    fn dyn_hash(&self, _: &mut dyn Hasher) {}
}

impl Serializable for CiphertextValidityProof {
    fn get_size(&self) -> usize {
        self.size()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(CIPHERTEXT_VALIDITY_PROOF_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }
}

pub fn ciphertext_validity_proof_verify(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let commitment = PedersenCommitment::from_point(
        params[0]
            .as_mut()
            .as_opaque_type_mut::<OpaqueRistrettoPoint>()?
            .decompressed()?
            .clone()
    );
    let dest_pubkey = PublicKey::from_point(
        params[1]
            .as_mut()
            .as_opaque_type_mut::<OpaqueRistrettoPoint>()?
            .decompressed()?
            .clone()
    );
    let source_pubkey = PublicKey::from_point(
        params[2]
            .as_mut()
            .as_opaque_type_mut::<OpaqueRistrettoPoint>()?
            .decompressed()?
            .clone()
    );
    let dest_handle = DecryptHandle::from_point(
        params[3]
            .as_mut()
            .as_opaque_type_mut::<OpaqueRistrettoPoint>()?
            .decompressed()?
            .clone()
    );
    let source_handle = DecryptHandle::from_point(
        params[4]
            .as_mut()
            .as_opaque_type_mut::<OpaqueRistrettoPoint>()?
            .decompressed()?
            .clone()
    );
    let transcript: &mut OpaqueTranscript = params[5]
        .as_mut()
        .as_opaque_type_mut()?;

    let zelf = zelf?;
    let zelf: &CiphertextValidityProof = zelf.as_opaque_type()?;
    let valid = zelf.verify(&commitment, &dest_pubkey, &source_pubkey, &dest_handle, &source_handle, true, &mut transcript.0)
        .is_ok();

    Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
}
