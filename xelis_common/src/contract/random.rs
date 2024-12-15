use anyhow::Context;
use blake3::OutputReader;

use crate::crypto::Hash;

// Deterministic random number generator
// This is used to generate random numbers in a deterministic way
// It is based on the blake3 hash function
#[derive(Debug, Clone)]
pub struct DeterministicRandom {
    // Key for the random number generator
    reader: OutputReader,
    // Blake3 support up to 2^64 - 1 bytes
    // We need to check pos is less than 2^64 - 1
    pos: u64,
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
            pos: 0,
        }
    }

    pub fn fill(&mut self, buffer: &mut [u8]) -> Result<(), anyhow::Error> {
        self.pos = self.pos.checked_add(buffer.len() as u64)
            .context("Random number generator overflow")?;

        if self.pos == u64::MAX - 1 {
            return Err(anyhow::anyhow!("2^64 - 1 bytes reached"));
        }

        self.reader.fill(buffer);

        Ok(())
    }
}