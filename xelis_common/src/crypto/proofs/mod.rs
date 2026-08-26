mod ciphertext_validity;
mod commitment_eq;
mod range_proof;
mod balance;
mod ownership;
mod arbitrary_range;

use std::iter;
use curve25519_dalek::{
    traits::{IsIdentity, VartimeMultiscalarMul},
    RistrettoPoint,
    Scalar
};
use lazy_static::lazy_static;
use thiserror::Error;
use bulletproofs::{BulletproofGens, PedersenGens};
use crate::transaction::MAX_TRANSFER_COUNT;
use super::{
    elgamal::DecompressionError,
    non_zero_random_scalar,
    rng,
    TranscriptError
};

// Exports
pub use commitment_eq::CommitmentEqProof;
pub use ciphertext_validity::CiphertextValidityProof;
pub use balance::BalanceProof;
pub use ownership::OwnershipProof;
pub use range_proof::RangeProof;
pub use arbitrary_range::ArbitraryRangeProof;

// We are using 64 bits for the bulletproofs
pub const BULLET_PROOF_SIZE: usize = 64;

lazy_static! {
    // Bulletproof generators: party size is max transfers * 2 + 1
    // * 2 in case each transfer use a unique asset + 1 for xelis asset as fee and + 1 to be a power of 2
    pub static ref BP_GENS: BulletproofGens = BulletproofGens::new(BULLET_PROOF_SIZE, MAX_TRANSFER_COUNT * 2 + 2);
    pub static ref PC_GENS: PedersenGens = PedersenGens::default();
    // Re-export the base points for convenience
    pub static ref G: RistrettoPoint = PC_GENS.B;
    pub static ref H: RistrettoPoint = PC_GENS.B_blinding;
}

#[derive(Error, Debug, Clone, Copy, Eq, PartialEq)]
#[error("batch multiscalar mul returned non identity point")]
pub struct MultiscalarMulVerificationError;

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ProofGenerationError {
    #[error(transparent)]
    Decompression(#[from] DecompressionError),
    #[error("not enough funds in the account, required: {required}, available: {available}")]
    InsufficientFunds {
        required: u64,
        available: u64,
    },
    #[error("range proof generation failed: {0}")]
    RangeProof(#[from] bulletproofs::ProofError),
    #[error("invalid format")]
    Format,
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ProofVerificationError {
    #[error("invalid format: {0}")]
    Decompression(#[from] DecompressionError),
    #[error("commitment equality proof verification failed")]
    CommitmentEqProof,
    #[error("ciphertext validity proof verification failed")]
    CiphertextValidityProof,
    #[error("proof verification failed")]
    GenericProof,
    #[error("range proof verification failed: {0}")]
    RangeProof(#[from] bulletproofs::ProofError),
    #[error("transcript error: {0}")]
    Transcript(#[from] TranscriptError),
    #[error("invalid format")]
    Format,
    #[error(transparent)]
    BatchVerificationError(#[from] MultiscalarMulVerificationError),
}


#[derive(Default)]
pub struct BatchCollector {
    dynamic_scalars: Vec<Scalar>,
    dynamic_points: Vec<RistrettoPoint>,
    g_scalar: Scalar,
    h_scalar: Scalar,
}

pub(crate) struct BatchCollectorEntry<'a> {
    collector: &'a mut BatchCollector,
    factor: Scalar,
}

impl BatchCollector {
    /// Start collecting one proof verification equation.
    ///
    /// Each complete proof equation is multiplied by one verifier-chosen
    /// random factor. This prevents invalid proofs from cancelling each other
    /// when several proofs or transactions are verified in the same batch.
    pub(crate) fn begin_proof(&mut self) -> BatchCollectorEntry<'_> {
        BatchCollectorEntry {
            collector: self,
            factor: non_zero_random_scalar(&mut rng()),
        }
    }

    pub fn verify(&self) -> Result<(), MultiscalarMulVerificationError> {
        let mega_check = RistrettoPoint::vartime_multiscalar_mul(
            self.dynamic_scalars
                .iter()
                .chain(iter::once(&self.g_scalar))
                .chain(iter::once(&self.h_scalar)),
            self.dynamic_points
                .iter()
                .cloned()
                .chain(iter::once(*G))
                .chain(iter::once(*H)),
        );

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(MultiscalarMulVerificationError)
        }
    }
}

impl BatchCollectorEntry<'_> {
    pub(crate) fn add_g_scalar(&mut self, scalar: Scalar) {
        self.collector.g_scalar += scalar * self.factor;
    }

    pub(crate) fn add_h_scalar(&mut self, scalar: Scalar) {
        self.collector.h_scalar += scalar * self.factor;
    }

    pub(crate) fn extend<const N: usize>(
        &mut self,
        scalars: [Scalar; N],
        points: [&RistrettoPoint; N],
    ) {
        self.collector
            .dynamic_scalars
            .extend(scalars.into_iter().map(|scalar| scalar * self.factor));
        self.collector
            .dynamic_points
            .extend(points.into_iter().cloned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_one_random_factor_per_proof() {
        let mut collector = BatchCollector::default();

        // Terms within one proof keep the same factor and still cancel as part
        // of that proof's verification equation.
        {
            let mut proof = collector.begin_proof();
            proof.extend(
                [Scalar::ONE, -Scalar::ONE],
                [&G, &G],
            );
        }
        assert!(collector.verify().is_ok());

        // Equal and opposite residuals from distinct proofs receive distinct
        // verifier-side factors and cannot be deliberately cancelled.
        let mut collector = BatchCollector::default();
        {
            let mut proof = collector.begin_proof();
            proof.extend([Scalar::ONE], [&G]);
        }
        {
            let mut proof = collector.begin_proof();
            proof.extend([-Scalar::ONE], [&G]);
        }
        assert!(collector.verify().is_err());
    }
}
