use xelis_vm::Opaque;
use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto, traits::IsIdentity};
use schemars::JsonSchema;
use serde::{
    de::Error,
    ser::Error as SerializeError,
    Deserialize,
    Deserializer,
    Serialize,
    Serializer as SerdeSerializer,
};
use sha3::{Digest, Sha3_512};
use crate::{
    crypto::proofs::H,
    serializer::{
        Error as SerializationError,
        Readable,
        Reader,
        ReaderError,
        Serializer,
        Writable,
        Writer,
    },
};
use super::{PublicKey, SCALAR_SIZE};

pub const SIGNATURE_SIZE: usize = SCALAR_SIZE * 2;

/// An ElGamal signature consisting of two Scalars (s and e)
#[derive(Clone, Debug, Eq, PartialEq, Hash, JsonSchema)]
#[schemars(with = "String")]
#[derive(Opaque)]
#[opaque(json, serializable, hash, eq)]
pub struct Signature {
    s: Scalar,
    e: Scalar,
}

impl Signature {
    pub fn new(s: Scalar, e: Scalar) -> Self {
        Self { s, e }
    }

    // Verify the signature using the Public Key and the hash of the message
    pub fn verify_internal(&self, message: &[u8], key: &RistrettoPoint, key_compressed: &CompressedRistretto) -> bool {
        if key.is_identity() {
            return false;
        }

        let r = (*H) * &self.s + key * -self.e;
        let calculated = hash_and_point_to_scalar(&key_compressed, message, &r);
        self.e == calculated
    }

    // Verify the signature using the Public Key and the hash of the message
    pub fn verify(&self, message: &[u8], key: &PublicKey) -> bool {
        let key_compressed = key.as_point().compress();
        self.verify_internal(message, &key.as_point(), &key_compressed)
    }
}

// Create a Scalar from Public Key, Hash of the message, and selected point
pub fn hash_and_point_to_scalar(key: &CompressedRistretto, message: &[u8], point: &RistrettoPoint) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(key.as_bytes());
    hasher.update(message);
    hasher.update(point.compress().as_bytes());

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.try_into().unwrap())
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: SerdeSerializer
    {
        serializer.serialize_str(&hex::encode(&self.to_bytes().map_err(SerializeError::custom)?))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from_hex(&s).map_err(D::Error::custom)?)
    }
}

impl Serializer for Signature {
    fn write<'ty, 'r, W: Writable>(&self, writer: &mut Writer<'ty, 'r, W>) -> Result<(), SerializationError> {
        writer.write_with_context::<Self>(|writer| {
            self.s.write(writer)?;
            self.e.write(writer)
        })
    }

    fn read<'ty, 'r, R: Readable>(reader: &mut Reader<'ty, 'r, R>) -> Result<Self, ReaderError> {
        reader.read_with_context(|reader| {
            let s = Scalar::read(reader)?;
            let e = Scalar::read(reader)?;
            Ok(Signature::new(s, e))
        })
    }

    fn size(&self) -> usize {
        SIGNATURE_SIZE
    }
}