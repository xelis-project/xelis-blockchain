use curve25519_dalek::Scalar;
use merlin::Transcript;
use super::{
    elgamal::{
        Ciphertext,
        PedersenCommitment,
        PedersenOpening,
        PublicKey
    },
    proofs::{
        BatchCollector,
        CommitmentEqProof,
        ProofVerificationError,
    },
    KeyPair, ProtocolTranscript
};

/// A balance proof is a cryptographic proof to reveal the balance of an account securely.
/// When Alice wants to prove to Bob that she has a certain amount of money, she can use a balance proof.
/// The balance proof is a zero-knowledge proof that proves that the difference between the balance ciphertext and the commitment of the balance amount is zero.
/// In other words, the balance proof proves that the balance amount is equal to the amount that was encrypted in the ciphertext.
/// The advantage of a Balance proof is to provide a one time proof that is outdated once the balance is again updated.
pub struct BalanceProof {
    /// The expected balance amount.
    amount: u64,
    /// The commitment proof.
    commitment_eq_proof: CommitmentEqProof,
}

impl BalanceProof {
    /// The opening used for the balance proof.
    /// This is a constant value that is used to generate & verify the balance proof.
    /// We use a constant opening to gain some space and because we don't need to hide the opening.
    const OPENING: PedersenOpening = PedersenOpening::from_scalar(Scalar::ONE);

    /// Create a new balance proof.
    pub fn new(amount: u64, commitment_eq_proof: CommitmentEqProof) -> Self {
        Self { amount, commitment_eq_proof }
    }

    /// Prove the balance proof.
    pub fn prove(keypair: &KeyPair, amount: u64, ciphertext: Ciphertext, transcript: &mut Transcript) -> Self {
        // Compute the zeroed balance
        let ct = keypair.get_public_key().encrypt_with_opening(amount, &Self::OPENING);
        let zeroed_balance = ciphertext - ct;

        transcript.balance_proof_domain_separator();
        // Generate the proof that the final balance is 0 after applying the commitment.
        let commitment_eq_proof = CommitmentEqProof::new(keypair, &zeroed_balance, &Self::OPENING, 0, transcript);

        Self::new(amount, commitment_eq_proof)
    }

    /// Verify the balance proof.
    pub fn verify(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript, batch_collector: &mut BatchCollector) -> Result<(), ProofVerificationError> {
        // Calculate the commitment that corresponds to the balance amount.
        let destination_commitment = PedersenCommitment::new_with_opening(Scalar::ZERO, &Self::OPENING);

        // Compute the zeroed balance
        let ct = public_key.encrypt_with_opening(self.amount, &Self::OPENING);
        let zeroed_balance = source_ciphertext - ct;

        transcript.balance_proof_domain_separator();
        self.commitment_eq_proof.pre_verify(public_key, &zeroed_balance, &destination_commitment, transcript, batch_collector)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_balance_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let amount = 100u64;
        let ct = keypair.get_public_key().encrypt(amount);

        // Create proof
        let mut transcript = Transcript::new(b"test");
        let proof = BalanceProof::prove(&keypair, amount, ct.clone(), &mut transcript);

        // Verify the proof
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();
        assert!(proof.verify(keypair.get_public_key(), ct, &mut transcript, &mut batch_collector).is_ok());
        assert!(batch_collector.verify().is_ok());
    }

    #[test]
    fn test_invalid_amount_balance_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let amount = 100u64;
        let ct = keypair.get_public_key().encrypt(amount);

        // Create proof with a lower amount than our balance
        let mut transcript = Transcript::new(b"test");
        let proof = BalanceProof::prove(&keypair, 95, ct.clone(), &mut transcript);

        // Verify the proof
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();

        proof.verify(keypair.get_public_key(), ct, &mut transcript, &mut batch_collector).unwrap();
        assert!(batch_collector.verify().is_err());
    }

    #[test]
    fn test_invalid_balance_ciphertext_balance_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let amount = 100u64;
        let ct = keypair.get_public_key().encrypt(amount);

        // Create proof with a lower amount than our balance
        let mut transcript = Transcript::new(b"test");
        let proof = BalanceProof::prove(&keypair, amount, ct, &mut transcript);

        // Verify the proof
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();

        // Generate another ciphertext with same amount
        let ct = keypair.get_public_key().encrypt(amount);

        proof.verify(keypair.get_public_key(), ct, &mut transcript, &mut batch_collector).unwrap();
        assert!(batch_collector.verify().is_err());
    }
}