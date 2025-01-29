use std::hash::Hasher;

use serde::{Deserialize, Serialize};
use xelis_vm::{impl_opaque, traits::{DynHash, Serializable}};
use crate::{
    account::CiphertextCache,
    contract::CIPHERTEXT_OPAQUE_ID,
    crypto::elgamal::RISTRETTO_COMPRESSED_SIZE,
    serializer::{Serializer, Writer}
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueCiphertext(pub CiphertextCache);

impl Serializable for OpaqueCiphertext {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(CIPHERTEXT_OPAQUE_ID);
        self.0.write(&mut writer);
        writer.total_write()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn get_size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE + RISTRETTO_COMPRESSED_SIZE
    }
}

impl DynHash for OpaqueCiphertext {
    fn dyn_hash(&self, _: &mut dyn Hasher) {
        // nothing
    }
}

impl_opaque!(
    "Ciphertext",
    OpaqueCiphertext
);
impl_opaque!(
    "Ciphertext",
    OpaqueCiphertext,
    json
);