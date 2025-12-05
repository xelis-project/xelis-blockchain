use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, Scalar};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use schemars::*;
use crate::{
    api::DataElement,
    crypto::{Address, AddressType},
    serializer::*
};
use super::{Ciphertext, DecryptHandle, PedersenCommitment, PublicKey};

// Compressed point size in bytes
pub const RISTRETTO_COMPRESSED_SIZE: usize = 32;
// Scalar size in bytes
pub const SCALAR_SIZE: usize = 32;

#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[error("point decompression failed")]
pub struct DecompressionError;

/// A Pedersen commitment compressed to 32 bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(with = "Vec<u8>")]
pub struct CompressedCommitment(CompressedRistretto);

/// A decrypt handle compressed to 32 bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(with = "Vec<u8>")]
pub struct CompressedHandle(CompressedRistretto);

/// A compressed ciphertext that can be serialized and deserialized with only 64 bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(with = "Vec<u8>")]
pub struct CompressedCiphertext {
    commitment: CompressedCommitment,
    handle: CompressedHandle
}

/// A compressed public key using only 32 bytes
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(with = "Vec<u8>")]
pub struct CompressedPublicKey(CompressedRistretto);

impl CompressedCommitment {
    // Create a new compressed commitment
    pub fn new(point: CompressedRistretto) -> Self {
        Self(point)
    }

    // Commitment as 32 bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0.as_bytes()
    }

    // Compressed commitment as a compressed point
    pub fn as_point(&self) -> &CompressedRistretto {
        &self.0
    }

    // Decompress it to a PedersenCommitment
    pub fn decompress(&self) -> Result<PedersenCommitment, DecompressionError> {
        self.0.decompress().map(PedersenCommitment::from_point).ok_or(DecompressionError)
    }
}

impl CompressedHandle {
    // Create a new compressed handle
    pub fn new(point: CompressedRistretto) -> Self {
        Self(point)
    }

    // Handle as 32 bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0.as_bytes()
    }

    // Decompress it to a DecryptHandle
    pub fn decompress(&self) -> Result<DecryptHandle, DecompressionError> {
        self.0.decompress().map(DecryptHandle::from_point).ok_or(DecompressionError)
    }
}

impl CompressedCiphertext {
    // Create a new compressed ciphertext
    pub fn new(commitment: CompressedCommitment, handle: CompressedHandle) -> Self {
        Self { commitment, handle }
    }

    // Create a ciphertext representing ZERO
    pub fn zero() -> Self {
        Self {
            commitment: CompressedCommitment::new(CompressedRistretto::identity()),
            handle: CompressedHandle::new(CompressedRistretto::identity()),
        }
    }

    // Serialized commitment
    pub fn commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    // Serialized handle
    pub fn handle(&self) -> &CompressedHandle {
        &self.handle
    }

    // Ciphertext as 64 bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; RISTRETTO_COMPRESSED_SIZE * 2];
        let commitment = self.commitment.as_bytes();
        let handle = self.handle.as_bytes();

        bytes[0..RISTRETTO_COMPRESSED_SIZE].copy_from_slice(commitment);
        bytes[RISTRETTO_COMPRESSED_SIZE..RISTRETTO_COMPRESSED_SIZE * 2].copy_from_slice(handle);

        bytes
    }

    // Decompress it to a Ciphertext
    pub fn decompress(&self) -> Result<Ciphertext, DecompressionError> {
        let commitment = self.commitment.decompress()?;
        let handle = self.handle.decompress()?;

        Ok(Ciphertext::new(commitment, handle))
    }
}

impl CompressedPublicKey {
    // Create a new compressed public key
    pub fn new(point: CompressedRistretto) -> Self {
        Self(point)
    }

    // Serialized public key
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0.as_bytes()
    }

    // Decompress it to a Public Key
    pub fn decompress(&self) -> Result<PublicKey, DecompressionError> {
        self.0.decompress().map(PublicKey::from_point).ok_or(DecompressionError)
    }

    // Clone the key to convert it to an address
    pub fn as_address(&self, mainnet: bool) -> Address {
        self.clone().to_address(mainnet)
    }

    // Convert it to an address
    pub fn to_address(self, mainnet: bool) -> Address {
        Address::new(mainnet, AddressType::Normal, self)
    }

    // Convert it to an address with data integrated
    pub fn to_address_with(self, mainnet: bool, data: DataElement) -> Address {
        Address::new(mainnet, AddressType::Data(data), self)
    }

    pub fn as_point(&self) -> &CompressedRistretto {
        &self.0
    }
}

impl Serializer for CompressedRistretto {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(self.as_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let bytes = reader.read_bytes_ref(RISTRETTO_COMPRESSED_SIZE)?;
        let point = CompressedRistretto::from_slice(bytes)?;

        Ok(point)
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE
    }
}

impl Serializer for CompressedCommitment {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        CompressedRistretto::read(reader).map(CompressedCommitment::new)
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

impl Serializer for CompressedHandle {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        CompressedRistretto::read(reader).map(CompressedHandle::new)
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

impl Serializer for CompressedPublicKey {
    fn write(&self, writer: &mut Writer) {
        self.0.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        CompressedRistretto::read(reader).map(CompressedPublicKey::new)
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

impl Serializer for CompressedCiphertext {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(self.commitment.as_bytes());
        writer.write_bytes(self.handle.as_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let commitment = CompressedCommitment::read(reader)?;
        let handle = CompressedHandle::read(reader)?;

        let compress = CompressedCiphertext::new(commitment, handle);
        Ok(compress)
    }

    fn size(&self) -> usize {
        self.commitment.size() + self.handle.size()
    }
}

impl Serializer for Scalar {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(self.as_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let bytes = reader.read_bytes(SCALAR_SIZE)?;
        let scalar: Option<Scalar> = Scalar::from_canonical_bytes(bytes).into();
        scalar.ok_or(ReaderError::InvalidValue)
    }

    fn size(&self) -> usize {
        SCALAR_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compressed_ciphertext_zero() {
        let ciphertext = Ciphertext::zero();
        let compressed = ciphertext.compress();
        let decompressed = compressed.decompress().unwrap();

        assert_eq!(ciphertext, decompressed);
    }

    #[test]
    fn test_compressed_ciphertext_serde() {
        let ciphertext = Ciphertext::zero();
        let json  = json!(ciphertext);

        let deserialized: Ciphertext = serde_json::from_value(json).unwrap();
        assert_eq!(ciphertext, deserialized);
    }
}