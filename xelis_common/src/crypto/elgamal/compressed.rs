use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedCiphertext {
    commitment: CompressedCommitment,
    handle: CompressedRistretto
}


impl CompressedCommitment {
    pub fn new(point: CompressedRistretto) -> Self {
        Self(point)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0.as_bytes()
    }

    pub fn decompress(&self) -> Result<RistrettoPoint, DecompressionError> {
        self.0.decompress().ok_or(DecompressionError)
    }
}

impl CompressedCiphertext {
    pub fn new(commitment: CompressedCommitment, handle: CompressedRistretto) -> Self {
        Self { commitment, handle }
    }

    // Serialized commitment
    pub fn commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    // Serialized handle
    pub fn handle(&self) -> &CompressedRistretto {
        &self.handle
    }

    // Decompress it to a Ciphertext
    pub fn decompress(&self) -> Result<Ciphertext, DecompressionError> {
        let point = self.commitment.decompress()?;
        let commitment = PedersenCommitment::from_point(point);
        let handle = DecryptHandle::from_point(self.handle.decompress().ok_or(DecompressionError)?);

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
            CompressedRistretto(handle)
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