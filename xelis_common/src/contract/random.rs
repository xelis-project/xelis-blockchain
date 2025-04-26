use anyhow::Context;
use blake3::OutputReader;

use crate::crypto::Hash;

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
    pub fn new(contract: &Hash, block: &Hash, transaction: &Hash) -> Self {
        let reader = blake3::Hasher::new()
            .update(contract.as_bytes())
            .update(block.as_bytes())
            .update(transaction.as_bytes())
            .finalize_xof();

        Self {
            reader,
        }
    }

    pub fn fill(&mut self, buffer: &mut [u8]) -> Result<(), anyhow::Error> {
        let pos = self.reader.position()
            .checked_add(buffer.len() as u64)
            .context("overflow")?;

        if pos >= u64::MAX - 1 {
            return Err(anyhow::anyhow!("2^64 - 1 bytes reached"));
        }

        self.reader.fill(buffer);

        Ok(())
    }
}