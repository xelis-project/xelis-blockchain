use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use serde::{Deserialize, Serialize};
use xelis_vm::{impl_opaque, traits::Serializable};

use crate::{
    contract::{RISTRETTO_OPAQUE_ID, SCALAR_OPAQUE_ID},
    crypto::elgamal::{RISTRETTO_COMPRESSED_SIZE, SCALAR_SIZE},
    serializer::*
};

impl_opaque!("RistrettoPoint", OpaqueRistrettoPoint, json);
impl_opaque!("RistrettoPoint", OpaqueRistrettoPoint);

impl_opaque!("Scalar", OpaqueScalar, json);
impl_opaque!("Scalar", OpaqueScalar);


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpaqueRistrettoPoint(pub CompressedRistretto);

impl Serializable for OpaqueRistrettoPoint {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(RISTRETTO_OPAQUE_ID);
        self.0.write(&mut writer);
        writer.total_write()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn get_size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpaqueScalar(pub Scalar);

impl Serializable for OpaqueScalar {
    fn serialize(&self, buffer: &mut Vec<u8>) -> usize {
        let mut writer = Writer::new(buffer);
        writer.write_u8(SCALAR_OPAQUE_ID);
        self.0.write(&mut writer);
        writer.total_write()
    }

    fn is_serializable(&self) -> bool {
        true
    }

    fn get_size(&self) -> usize {
        SCALAR_SIZE
    }
}