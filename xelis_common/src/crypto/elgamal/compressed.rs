use curve25519_dalek::ristretto::CompressedRistretto;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::serializer::{Reader, ReaderError, Serializer, Writer};
use super::{Ciphertext, DecryptHandle, PedersenCommitment};

// Compressed point size in bytes
pub const RISTRETTO_COMPRESSED_SIZE: usize = 32;

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

impl CompressedCommitment {
    // Create a new compressed commitment
    pub fn new(point: CompressedRistretto) -> Self {
        Self(point)
    }

    // Commitment as 32 bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0.as_bytes()
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

    // Serialized commitment
    pub fn commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    // Serialized handle
    pub fn handle(&self) -> &CompressedHandle {
        &self.handle
    }

    // Decompress it to a Ciphertext
    pub fn decompress(&self) -> Result<Ciphertext, DecompressionError> {
        let commitment = self.commitment.decompress()?;
        let handle = self.handle.decompress()?;

        Ok(Ciphertext::new(commitment, handle))
    }
}

impl Serializer for CompressedCiphertext {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(self.commitment.as_bytes());
        writer.write_bytes(self.handle.as_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let commitment = reader.read_bytes(RISTRETTO_COMPRESSED_SIZE)?;
        let handle = reader.read_bytes(RISTRETTO_COMPRESSED_SIZE)?;

        let compress = CompressedCiphertext::new(
            CompressedCommitment::new(CompressedRistretto(commitment)),
            CompressedHandle::new(CompressedRistretto(handle))
        );
        Ok(compress)
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE + RISTRETTO_COMPRESSED_SIZE
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