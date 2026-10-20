
use xelis_vm::{
    traits::DynSerializable,
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult
};
use crate::{
    contract::{
        opaque::CIPHERTEXT_VALIDITY_PROOF_OPAQUE_ID,
        ContractMetadata,
        ModuleMetadata,
        OpaqueRistrettoPoint,
        OpaqueTranscript
    },
    crypto::{elgamal::{DecryptHandle, PedersenCommitment, PublicKey}, proofs::CiphertextValidityProof},
    serializer::{Error as SerializationError, *},
};

impl DynSerializable for CiphertextValidityProof {
    fn get_size(&self) -> usize {
        self.size()
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        writer.write_u8(CIPHERTEXT_VALIDITY_PROOF_OPAQUE_ID)?;
        self.write(&mut writer)?;
        Ok(buffer.len() - start)
    }
}

pub fn ciphertext_validity_proof_verify(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
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
    let valid = zelf.verify(&commitment, &dest_pubkey, &source_pubkey, &dest_handle, &source_handle, &mut transcript.0)
        .is_ok();

    Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
}
