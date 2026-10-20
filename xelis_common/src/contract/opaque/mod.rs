mod transaction;
mod address;
mod random;
mod block;
mod storage;
mod asset;
mod crypto;
mod memory_storage;
mod contract;

use bulletproofs::RangeProof;
use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use log::debug;
use std::fmt::{Formatter, Result as FmtResult};
use serde_json::Value;
use matriochka::ResultExt;
use silex_types::register_opaque_json;
use xelis_vm::{Opaque, OpaqueWrapper, ValueError, tid, traits::{DynEq, DynHash, DynSerializable, JSONHelper, JSON_REGISTRY}};
use crate::{
    account::CiphertextCache,
    block::Block,
    crypto::{
        proofs::*,
        Address,
        Hash,
        Signature
    },
    serializer::{Error as SerializationError, *},
    transaction::Transaction
};
use super::ChainState;

pub use transaction::*;
pub use random::*;
pub use block::*;
pub use storage::*;
pub use address::*;
pub use asset::*;
pub use crypto::*;
pub use memory_storage::*;
pub use contract::*;

// Unique IDs for opaque types serialization
pub const HASH_OPAQUE_ID: u8 = 0;
pub const ADDRESS_OPAQUE_ID: u8 = 1;
pub const SIGNATURE_OPAQUE_ID: u8 = 2;
pub const CIPHERTEXT_OPAQUE_ID: u8 = 3;
pub const CIPHERTEXT_VALIDITY_PROOF_OPAQUE_ID: u8 = 4;
pub const COMMITMENT_EQUALITY_PROOF_OPAQUE_ID: u8 = 5;
pub const RANGE_PROOF_OPAQUE_ID: u8 = 6;
pub const ARBITRARY_RANGE_PROOF_OPAQUE_ID: u8 = 7;
pub const OWNERSHIP_PROOF_OPAQUE_ID: u8 = 8;
pub const BALANCE_PROOF_OPAQUE_ID: u8 = 9;
pub const RISTRETTO_OPAQUE_ID: u8 = 10;
pub const SCALAR_OPAQUE_ID: u8 = 11;

impl Opaque for Address {
    fn clone_box(&self) -> Box<dyn Opaque> {
        Box::new(self.clone())
    }

    fn as_serializable(&self) -> Option<&dyn DynSerializable> {
        Some(self)
    }

    fn as_hashable(&self) -> Option<&dyn DynHash> {
        Some(self)
    }

    fn as_eq(&self) -> Option<&dyn DynEq> {
        Some(self)
    }

    fn display(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Address({})", self)
    }

    fn validate(&self) -> Result<(), ValueError> {
        // Only allow normal addresses
        if !self.is_normal() {
            return Err(ValueError::InvalidOpaqueTypeMismatch);
        }

        Ok(())
    }
}

impl JSONHelper for Address {
    fn serialize_json(&self) -> Result<Value, SerializationError> {
        serde_json::to_value(self).context("serializing Address to JSON")
    }

    fn is_json_supported(&self) -> bool {
        true
    }
}

// Injectable context data
tid!(ChainState<'_>);
tid!(Hash);
tid!(Transaction);
tid!(Block);

// Register opaques types compatible with JSON serialization
pub fn register_opaque_types() {
    debug!("Registering opaque types");
    let mut registry = JSON_REGISTRY.write().expect("Failed to lock JSON_REGISTRY");
    register_opaque_json!(registry, "Hash", Hash);
    register_opaque_json!(registry, "Address", Address);
    register_opaque_json!(registry, "Signature", Signature);
    register_opaque_json!(registry, "Ciphertext", CiphertextCache);
    register_opaque_json!(registry, "CiphertextValidityProof", CiphertextValidityProof);
    register_opaque_json!(registry, "CommitmentEqualityProof", CommitmentEqProof);
    register_opaque_json!(registry, "RangeProof", RangeProofWrapper);
    register_opaque_json!(registry, "RistrettoPoint", OpaqueRistrettoPoint);
    register_opaque_json!(registry, "Scalar", OpaqueScalar);
}

impl Serializer for OpaqueWrapper {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            let mut bytes = Vec::new();
            self.as_serializable()
                .ok_or_else(|| SerializationError::new(ValueError::InvalidOpaqueTypeMismatch).context("opaque value does not support binary serialization"))?
                .serialize(&mut bytes)?;
            writer.write_bytes(&bytes)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            Ok(match reader.read_u8()? {
                HASH_OPAQUE_ID => OpaqueWrapper::new(Hash::read(reader)?),
                ADDRESS_OPAQUE_ID => OpaqueWrapper::new(Address::read(reader)?),
                SIGNATURE_OPAQUE_ID => OpaqueWrapper::new(Signature::read(reader)?),
                CIPHERTEXT_OPAQUE_ID => OpaqueWrapper::new(CiphertextCache::read(reader)?),
                CIPHERTEXT_VALIDITY_PROOF_OPAQUE_ID => OpaqueWrapper::new(CiphertextValidityProof::read(reader)?),
                COMMITMENT_EQUALITY_PROOF_OPAQUE_ID => OpaqueWrapper::new(CommitmentEqProof::read(reader)?),
                RANGE_PROOF_OPAQUE_ID => OpaqueWrapper::new(RangeProofWrapper(RangeProof::read(reader)?)),
                ARBITRARY_RANGE_PROOF_OPAQUE_ID => OpaqueWrapper::new(ArbitraryRangeProof::read(reader)?),
                OWNERSHIP_PROOF_OPAQUE_ID => OpaqueWrapper::new(OwnershipProof::read(reader)?),
                BALANCE_PROOF_OPAQUE_ID => OpaqueWrapper::new(BalanceProof::read(reader)?),
                RISTRETTO_OPAQUE_ID => OpaqueWrapper::new(OpaqueRistrettoPoint::Compressed(CompressedRistretto::read(reader)?)),
                SCALAR_OPAQUE_ID => OpaqueWrapper::new(OpaqueScalar(Scalar::read(reader)?)),
                tag => return Err(SerializationError::new(DecodeError::InvalidValue).context(format!("unknown opaque value tag {tag}")))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;

    use super::*;
    use serde_json::json;
    use xelis_vm::OpaqueWrapper;

    #[test]
    fn test_address_serde() {
        register_opaque_types();
        
        let address = KeyPair::new().get_public_key().to_address(true);
        let opaque = OpaqueWrapper::new(address.clone());
        let v = json!(opaque);

        let opaque: OpaqueWrapper = serde_json::from_value(v)
            .unwrap();
        let address2: Address = opaque.into_inner()
            .expect("Failed to unwrap");

        assert_eq!(address, address2);
    }

    #[test]
    fn test_hash_serde() {
        register_opaque_types();
        
        let hash = Hash::max();
        let opaque = OpaqueWrapper::new(hash.clone());
        let v = json!(opaque);

        let opaque: OpaqueWrapper = serde_json::from_value(v)
            .unwrap();
        let hash2: Hash = opaque.into_inner()
            .expect("Failed to unwrap");

        assert_eq!(hash, hash2);
    }
}