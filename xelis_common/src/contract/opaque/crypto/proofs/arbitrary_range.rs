
use matriochka::ResultExt;
use xelis_vm::{
    ValueCell,
    PrimitiveInteger,
    traits::DynSerializable,
    VMContext,
    FnInstance,
    FnParams,
    FnReturnType,
    Primitive,
    SysCallResult
};
use crate::{
    account::CiphertextCache,
    contract::{
        ContractMetadata,
        ModuleMetadata,
        OpaqueRistrettoPoint,
        OpaqueTranscript,
        RangeProofWrapper,
        opaque::ARBITRARY_RANGE_PROOF_OPAQUE_ID
    },
    crypto::{
        elgamal::{CompressedCommitment, PublicKey},
        proofs::{ArbitraryRangeProof, CommitmentEqProof}
    },
    serializer::{Error as SerializationError, *},
};

impl DynSerializable for ArbitraryRangeProof {
    fn get_size(&self) -> usize {
        self.size()
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializationError> {
        let start = buffer.len();
        let mut writer = Writer::new(&mut *buffer);
        ARBITRARY_RANGE_PROOF_OPAQUE_ID.write(&mut writer)?;
        self.write(&mut writer)?;
        Ok(buffer.len() - start)
    }
}

pub fn arbitrary_range_proof_new(_: FnInstance, params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let max_value = params[0]
        .as_u64()
        .context("Failed to get max value parameter")?;
    let delta_commitment = CompressedCommitment::new(params[1]
            .as_ref()
            .as_opaque_type::<OpaqueRistrettoPoint>()?
            .compressed()
            .into_owned()
        );
    let commitment_eq_proof = params[2]
        .as_ref()
        .as_opaque_type::<CommitmentEqProof>()?
        .clone();
    let range_proof = params[3]
        .as_ref()
        .as_opaque_type::<RangeProofWrapper>()?
        .0
        .clone();

    let proof = ArbitraryRangeProof::from(max_value, delta_commitment, commitment_eq_proof, range_proof);

    Ok(SysCallResult::Return(ValueCell::Opaque(proof.into()).into()))
}

pub fn arbitrary_range_proof_max_value(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let zelf: &ArbitraryRangeProof = zelf.as_opaque_type()?;
    let max_value = zelf.max_value();

    Ok(SysCallResult::Return(Primitive::Integer(PrimitiveInteger::U64(max_value)).into()))
}

pub fn arbitrary_range_proof_delta_commitment(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let zelf: &ArbitraryRangeProof = zelf.as_opaque_type()?;
    let delta_commitment = zelf.delta_commitment();

    Ok(SysCallResult::Return(ValueCell::Opaque(OpaqueRistrettoPoint::Compressed(delta_commitment.as_point().clone()).into()).into()))
}

pub fn arbitrary_range_proof_commitment_eq_proof(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let zelf: &ArbitraryRangeProof = zelf.as_opaque_type()?;
    let commitment_eq_proof = zelf.commitment_eq_proof();

    Ok(SysCallResult::Return(ValueCell::Opaque(commitment_eq_proof.clone().into()).into()))
}

pub fn arbitrary_range_proof_range_proof(zelf: FnInstance, _: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let zelf = zelf?;
    let zelf: &ArbitraryRangeProof = zelf.as_opaque_type()?;
    let range_proof = zelf.range_proof();

    Ok(SysCallResult::Return(ValueCell::Opaque(RangeProofWrapper(range_proof.clone()).into()).into()))
}

pub fn arbitrary_range_proof_verify(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata<'_>, _: &mut VMContext) -> FnReturnType<ContractMetadata> {
    let source_pubkey = PublicKey::from_point(
        params[0]
            .as_mut()
            .as_opaque_type_mut::<OpaqueRistrettoPoint>()?
            .decompressed()?
            .clone()
    );
    let source_ciphertext = params[1]
        .as_mut()
        .as_opaque_type_mut::<CiphertextCache>()?
        .decompressed()
        .context("Couldn't decompress source ciphertext")?
        .clone();

    let transcript: &mut OpaqueTranscript = params[2]
        .as_mut()
        .as_opaque_type_mut()?;

    let zelf = zelf?;
    let zelf: &ArbitraryRangeProof = zelf.as_opaque_type()?;
    let valid = zelf.verify(&source_pubkey, &source_ciphertext, &mut transcript.0)
        .is_ok();

    Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
}
