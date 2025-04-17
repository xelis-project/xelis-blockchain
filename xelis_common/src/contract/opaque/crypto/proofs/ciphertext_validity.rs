use std::hash::Hasher;

use xelis_vm::{impl_opaque, traits::{DynEq, DynHash, Serializable}};
use crate::{
    contract::opaque::CIPHERTEXT_VALIDITY_PROOF_OPAQUE_ID,
    crypto::proofs::CiphertextValidityProof,
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