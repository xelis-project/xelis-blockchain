use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::{api::DataElement, crypto::{Address, AddressType}, serializer::{Reader, ReaderError, Serializer, Writer}};
use super::{Ciphertext, DecryptHandle, PedersenCommitment, PublicKey};

// Compressed point size in bytes
pub const RISTRETTO_COMPRESSED_SIZE: usize = 32;
// Scalar size in bytes
pub const SCALAR_SIZE: usize = 32;

trait SerializableCompressedPoint {
    fn from_compressed_point(point: CompressedRistretto) -> Self;
    fn as_compressed_point(&self) -> &CompressedRistretto;
}

impl SerializableCompressedPoint for CompressedRistretto {
    fn from_compressed_point(point: CompressedRistretto) -> Self {
        point
    }

    fn as_compressed_point(&self) -> &CompressedRistretto {
        self
    }
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[error("point decompression failed")]
pub struct DecompressionError;

// A Pedersen commitment compressed to 32 bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedCommitment(CompressedRistretto);

// A decrypt handle compressed to 32 bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedHandle(CompressedRistretto);

// A compressed ciphertext that can be serialized and deserialized with only 64 bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedCiphertext {
    commitment: CompressedCommitment,
    handle: CompressedHandle
}

// A compressed public key using only 32 bytes
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
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

impl SerializableCompressedPoint for CompressedCommitment {
    fn from_compressed_point(point: CompressedRistretto) -> Self {
        Self::new(point)
    }

    fn as_compressed_point(&self) -> &CompressedRistretto {
        &self.0
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

impl SerializableCompressedPoint for CompressedHandle {
    fn from_compressed_point(point: CompressedRistretto) -> Self {
        Self::new(point)
    }

    fn as_compressed_point(&self) -> &CompressedRistretto {
        &self.0
    }
}

impl CompressedCiphertext {
    // Create a new compressed ciphertext
    pub fn new(commitment: CompressedCommitment, handle: CompressedHandle) -> Self {
        Self { commitment, handle }
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
}

impl SerializableCompressedPoint for CompressedPublicKey {
    fn from_compressed_point(point: CompressedRistretto) -> Self {
        Self::new(point)
    }

    fn as_compressed_point(&self) -> &CompressedRistretto {
        &self.0
    }
}

impl<T: SerializableCompressedPoint> Serializer for T {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(self.as_compressed_point().as_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let point = reader.read_bytes_ref(RISTRETTO_COMPRESSED_SIZE)?;
        let compress = CompressedRistretto::from_slice(point)?;
        Ok(Self::from_compressed_point(compress))
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE
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

    #[test]
    fn test_compressed_ciphertext_zero() {
        let ciphertext = Ciphertext::zero();
        let compressed = ciphertext.compress();
        let decompressed = compressed.decompress().unwrap();

        assert_eq!(ciphertext, decompressed);
    }
}