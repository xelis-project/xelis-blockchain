
use xelis_vm::{
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
    serializer::{Error as SerializationError, *},
};

impl DynSerializable for CommitmentEqProof {
    fn get_size(&self) -> usize {
        self.size()
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        writer.write_u8(COMMITMENT_EQUALITY_PROOF_OPAQUE_ID)?;
        self.write(&mut writer)?;
        Ok(buffer.len() - start)
    }
}

pub fn commitment_eq_proof_verify(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
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
        .map_err(|e| EnvironmentError::Any(SerializationError::new(e)))?
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
