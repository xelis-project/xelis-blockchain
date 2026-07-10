use std::{error::Error, fmt};

use blake3::OutputReader;
use rand::{TryCryptoRng, TryRng};

use crate::{block::TopoHeight, crypto::Hash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeterministicRandomError {
    PositionOverflow,
    Exhausted,
}

impl fmt::Display for DeterministicRandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PositionOverflow => write!(f, "deterministic random position overflow"),
            Self::Exhausted => write!(f, "deterministic random exhausted"),
        }
    }
}

impl Error for DeterministicRandomError {}

// Deterministic random number generator
// This is used to generate random numbers in a deterministic way
// It is based on the blake3 hash function
#[derive(Debug, Clone)]
pub struct DeterministicRandom {
    // Key for the random number generator
    // Blake3 support up to 2^64 - 1 bytes
    // We need to check pos is less than 2^64 - 1
    reader: OutputReader,
}

impl DeterministicRandom {
    pub fn new(contract: &Hash, block: &Hash, topoheight: TopoHeight, transaction: &Hash) -> Self {
        let mut hasher = blake3::Hasher::new();

        hasher
            .update(contract.as_bytes())
            .update(block.as_bytes())
            .update(&topoheight.to_be_bytes())
            .update(transaction.as_bytes());

        Self {
            reader: hasher.finalize_xof(),
        }
    }

    fn check_fill_len(&self, len: usize) -> Result<(), DeterministicRandomError> {
        let pos = self.reader.position()
            .checked_add(len as u64)
            .ok_or(DeterministicRandomError::PositionOverflow)?;

        if pos >= u64::MAX - 1 {
            return Err(DeterministicRandomError::Exhausted);
        }

        Ok(())
    }

    pub fn fill(&mut self, buffer: &mut [u8]) -> Result<(), DeterministicRandomError> {
        self.check_fill_len(buffer.len())?;
        self.reader.fill(buffer);

        Ok(())
    }
}

impl TryCryptoRng for DeterministicRandom {}

impl TryRng for DeterministicRandom {
    type Error = DeterministicRandomError;

    /// Return the next random `u32`.
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buffer = [0u8; 4];
        self.fill(&mut buffer)?;
        Ok(u32::from_le_bytes(buffer))
    }
    /// Return the next random `u64`.
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buffer = [0u8; 8];
        self.fill(&mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }

    /// Fill `dst` entirely with random data.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dest)
    }
}
