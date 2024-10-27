use curve25519_dalek::Scalar;
use merlin::Transcript;
use crate::crypto::{
    elgamal::{
        Ciphertext,
        PedersenCommitment,
        PedersenOpening,
        PublicKey
    },
    KeyPair,
    ProtocolTranscript
};
use super::{
    BatchCollector,
    CommitmentEqProof,
    ProofGenerationError,
    ProofVerificationError
};

/// Prove that the prover owns a certain amount (N > 0) of a given asset.
pub struct OwnershipProof {
    /// The amount of the asset.
    amount: u64,
    /// The commitment of the left balance.
    commitment: PedersenCommitment,
    /// The commitment proof.
    commitment_eq_proof: CommitmentEqProof,
}

impl OwnershipProof {
    /// The opening used for the balance proof.
    /// This is a constant value that is used to generate & verify the balance proof.
    /// We use a constant opening to gain some space and because we don't need to hide the opening.
    const OPENING: PedersenOpening = PedersenOpening::from_scalar(Scalar::ONE);

    pub fn new(amount: u64, commitment: PedersenCommitment, commitment_eq_proof: CommitmentEqProof) -> Self {
        Self { amount, commitment, commitment_eq_proof }
    }

    /// Prove the ownership of the asset.
    pub fn prove(keypair: &KeyPair, balance: u64, amount: u64, ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<Self, ProofGenerationError> {
        if amount == 0 {
            return Err(ProofGenerationError::Format);
        }

        let left = balance.checked_sub(amount)
            .ok_or(ProofGenerationError::InsufficientFunds)?;
        
        transcript.ownership_proof_domain_separator();
        transcript.append_u64(b"amount", amount);

        let opening = PedersenOpening::generate_new();
        let left_commitment = PedersenCommitment::new_with_opening(left, &opening);

        // Compute the balance left
        let ct = keypair.get_public_key().encrypt_with_opening(amount, &Self::OPENING);
        let ct_left = ciphertext - ct;

        // Generate the proof that the final balance is 0 after applying the commitment.
        let commitment_eq_proof = CommitmentEqProof::new(keypair, &ct_left, &opening, left, transcript);

        Ok(Self::new(amount, left_commitment, commitment_eq_proof))
    }

    /// Verify the ownership proof.
    pub fn pre_verify(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript, batch_collector: &mut BatchCollector) -> Result<(), ProofVerificationError> {
        if self.amount == 0 {
            return Err(ProofVerificationError::Format);
        }

        transcript.ownership_proof_domain_separator();
        transcript.append_u64(b"amount", self.amount);

        // Compute the zeroed balance
        let ct = public_key.encrypt_with_opening(self.amount, &Self::OPENING);
        let balance_left = source_ciphertext - ct;

        self.commitment_eq_proof.pre_verify(public_key, &balance_left, &self.commitment, transcript, batch_collector)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ownership_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let balance = 100u64;
        let amount = 10u64;
        let ct = keypair.get_public_key().encrypt(balance);

        // Create proof
        let mut transcript = Transcript::new(b"test");
        let proof = OwnershipProof::prove(&keypair, balance, amount, ct.clone(), &mut transcript).unwrap();

        // Verify the proof
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();
        assert!(proof.pre_verify(keypair.get_public_key(), ct, &mut transcript, &mut batch_collector).is_ok());
        assert!(batch_collector.verify().is_ok());
    }
}