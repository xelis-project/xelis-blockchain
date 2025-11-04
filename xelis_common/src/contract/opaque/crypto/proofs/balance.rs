use std::hash::Hasher;

use anyhow::Context as _;
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
    account::CiphertextCache,
    contract::{ModuleMetadata, OpaqueRistrettoPoint, OpaqueTranscript, opaque::BALANCE_PROOF_OPAQUE_ID},
    crypto::{
        elgamal::PublicKey,
        proofs::{BalanceProof, CommitmentEqProof}
    },
    serializer::*
};

impl_opaque!("BalanceProof", BalanceProof, json);
impl_opaque!("BalanceProof", BalanceProof);

impl DynEq for BalanceProof {
    fn is_equal(&self, _: &dyn DynEq) -> bool {
        false
    }

    fn as_eq(&self) -> &dyn DynEq {
        self
    }
}

impl DynHash for BalanceProof {
    fn dyn_hash(&self, _: &mut dyn Hasher) {}
}

impl Serializable for BalanceProof {
    fn get_size(&self) -> usize {
        self.size()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(BALANCE_PROOF_OPAQUE_ID);
        self.write(&mut writer);
        writer.total_write()
    }
}


pub fn balance_proof_new(_: FnInstance, params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let amount = params[0]
        .as_u64()
        .context("Failed to get amount parameter")?;
    let commitment_eq_proof = params[1]
        .as_ref()
        .as_opaque_type::<CommitmentEqProof>()?
        .clone();

    let proof = BalanceProof::from(amount, commitment_eq_proof);

    Ok(SysCallResult::Return(Primitive::Opaque(proof.into()).into()))
}

pub fn balance_proof_amount(zelf: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &BalanceProof = zelf.as_opaque_type()?;

    Ok(SysCallResult::Return(Primitive::U64(zelf.amount()).into()))
}

pub fn balance_proof_commitment_eq_proof(zelf: FnInstance, _: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
    let zelf = zelf?;
    let zelf: &BalanceProof = zelf.as_opaque_type()?;
    let commitment_eq_proof = zelf.commitment_eq_proof();

    Ok(SysCallResult::Return(Primitive::Opaque(commitment_eq_proof.clone().into()).into()))
}

pub fn balance_proof_verify(zelf: FnInstance, mut params: FnParams, _: &ModuleMetadata, _: &mut Context) -> FnReturnType<ModuleMetadata> {
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
    let zelf: &BalanceProof = zelf.as_opaque_type()?;
    let valid = zelf.verify(&source_pubkey, source_ciphertext, &mut transcript.0)
        .is_ok();

    Ok(SysCallResult::Return(Primitive::Boolean(valid).into()))
}
