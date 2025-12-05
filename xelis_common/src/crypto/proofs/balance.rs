use curve25519_dalek::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use crate::{
    crypto::{
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
        KeyPair,
        ProtocolTranscript
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    },
    transaction::TxVersion
};

/// A balance proof is a cryptographic proof to reveal the balance of an account securely.
/// When Alice wants to prove to Bob that she has a certain amount of money, she can use a balance proof.
/// The balance proof is a zero-knowledge proof that proves that the difference between the balance ciphertext and the commitment of the balance amount is zero.
/// In other words, the balance proof proves that the balance amount is equal to the amount that was encrypted in the ciphertext.
/// The advantage of a Balance proof is to provide a one time proof that is outdated once the balance is again updated.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub fn from(amount: u64, commitment_eq_proof: CommitmentEqProof) -> Self {
        Self { amount, commitment_eq_proof }
    }

    /// Create a new balance proof
    pub fn new(keypair: &KeyPair, amount: u64, ciphertext: Ciphertext) -> Self {
        Self::prove(keypair, amount, ciphertext, &mut Transcript::new(b"balance_proof"))
    }

    /// Prove the balance proof using transcript.
    pub fn prove(keypair: &KeyPair, amount: u64, ciphertext: Ciphertext, transcript: &mut Transcript) -> Self {
        transcript.balance_proof_domain_separator();
        transcript.append_u64(b"amount", amount);
        transcript.append_ciphertext(b"source_ct", &ciphertext.compress());
        transcript.append_public_key(b"public_key", &keypair.get_public_key().compress());

        // Compute the zeroed balance
        let zeroed_balance = ciphertext - Scalar::from(amount);

        // Generate the proof that the final balance is 0 after applying the commitment.
        let commitment_eq_proof = CommitmentEqProof::new(keypair, &zeroed_balance, &Self::OPENING, 0u64, TxVersion::V2, transcript);

        Self::from(amount, commitment_eq_proof)
    }

    /// Get the amount being proven.
    #[inline]
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// Get the commitment equality proof.
    #[inline]
    pub fn commitment_eq_proof(&self) -> &CommitmentEqProof {
        &self.commitment_eq_proof
    }

    /// Internal verify function to avoid code duplication.
    fn verify_internal(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<(PedersenCommitment, Ciphertext), ProofVerificationError> {
        transcript.balance_proof_domain_separator();
        transcript.append_u64(b"amount", self.amount);
        transcript.append_ciphertext(b"source_ct", &source_ciphertext.compress());
        transcript.append_public_key(b"public_key", &public_key.compress());

        // Calculate the commitment that corresponds to the balance amount.
        let destination_commitment = PedersenCommitment::new_with_opening(Scalar::ZERO, &Self::OPENING);

        // Compute the zeroed balance
        let zeroed_balance = source_ciphertext - Scalar::from(self.amount);

        Ok((destination_commitment, zeroed_balance))
    }

    /// Verify the balance proof.
    pub fn pre_verify(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript, batch_collector: &mut BatchCollector) -> Result<(), ProofVerificationError> {
        let (destination_commitment, zeroed_balance) = self.verify_internal(public_key, source_ciphertext, transcript)?;
        self.commitment_eq_proof.pre_verify(public_key, &zeroed_balance, &destination_commitment, TxVersion::V2, transcript, batch_collector)
    }

    /// Verify the balance proof.
    pub fn verify(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<(), ProofVerificationError> {
        let (destination_commitment, zeroed_balance) = self.verify_internal(public_key, source_ciphertext, transcript)?;
        self.commitment_eq_proof.verify(public_key, &zeroed_balance, &destination_commitment, transcript)
    }
}

impl Serializer for BalanceProof {
    fn write(&self, writer: &mut Writer) {
        self.amount.write(writer);
        self.commitment_eq_proof.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let amount = u64::read(reader)?;
        let commitment_eq_proof = CommitmentEqProof::read(reader)?;

        Ok(Self::from(amount, commitment_eq_proof))
    }

    fn size(&self) -> usize {
        self.amount.size() + self.commitment_eq_proof.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let amount = 100u64;
        let ct = keypair.get_public_key().encrypt(amount);

        // Create proof
        let proof = BalanceProof::new(&keypair, amount, ct.clone());

        // Verify the proof
        assert!(proof.verify(keypair.get_public_key(), ct, &mut Transcript::new(b"balance_proof")).is_ok());
    }

    #[test]
    fn test_invalid_amount_balance_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let amount = 100u64;
        let ct = keypair.get_public_key().encrypt(amount);

        // Create proof with a lower amount than our balance
        let proof = BalanceProof::new(&keypair, 95, ct.clone());

        // Verify the proof
        assert!(proof.verify(keypair.get_public_key(), ct, &mut Transcript::new(b"balance_proof")).is_err());
    }

    #[test]
    fn test_invalid_balance_ciphertext_balance_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let amount = 100u64;
        let ct = keypair.get_public_key().encrypt(amount);

        // Create proof with a lower amount than our balance
        let proof = BalanceProof::new(&keypair, amount, ct);

        // Verify the proof
        // Generate another ciphertext with same amount
        let ct = keypair.get_public_key().encrypt(amount);

        assert!(proof.verify(keypair.get_public_key(), ct, &mut Transcript::new(b"balance_proof")).is_err());
    }
}