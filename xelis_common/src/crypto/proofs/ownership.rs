use curve25519_dalek::Scalar;
use merlin::Transcript;
use crate::{
    crypto::{
        elgamal::{
            Ciphertext,
            CompressedCommitment,
            PedersenCommitment,
            PedersenOpening,
            PublicKey
        },
        KeyPair,
        ProtocolTranscript
    },
    serializer::{
        Reader,
        ReaderError,
        Serializer,
        Writer
    }
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
    commitment: CompressedCommitment,
    /// The commitment proof.
    commitment_eq_proof: CommitmentEqProof,
}

impl OwnershipProof {
    /// The opening used for the proof.
    /// It is used to encrypt the amount of the asset that we want to prove.
    const OPENING: PedersenOpening = PedersenOpening::from_scalar(Scalar::ONE);

    pub fn new(amount: u64, commitment: CompressedCommitment, commitment_eq_proof: CommitmentEqProof) -> Self {
        Self { amount, commitment, commitment_eq_proof }
    }

    /// Prove the ownership of the asset.
    pub fn prove(keypair: &KeyPair, balance: u64, amount: u64, ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<Self, ProofGenerationError> {
        if amount == 0 {
            return Err(ProofGenerationError::Format);
        }

        let left = balance.checked_sub(amount)
            .ok_or(ProofGenerationError::InsufficientFunds)?;
        
        // We don't want to reveal the whole balance, so we create a new Commitment with a random opening.
        let opening = PedersenOpening::generate_new();
        let left_commitment = PedersenCommitment::new_with_opening(left, &opening)
            .compress();

        transcript.ownership_proof_domain_separator();
        transcript.append_u64(b"amount", amount);
        transcript.append_commitment(b"commitment", &left_commitment);

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
        transcript.append_commitment(b"commitment", &self.commitment);

        // Decompress the commitment
        let commitment = self.commitment.decompress()?;

        // Compute the balance left
        let ct = public_key.encrypt_with_opening(self.amount, &Self::OPENING);
        let balance_left = source_ciphertext - ct;

        self.commitment_eq_proof.pre_verify(public_key, &balance_left, &commitment, transcript, batch_collector)?;

        Ok(())
    }
}

impl Serializer for OwnershipProof {
    fn write(&self, writer: &mut Writer) {
        self.amount.write(writer);
        self.commitment.write(writer);
        self.commitment_eq_proof.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let amount = u64::read(reader)?;
        let commitment = CompressedCommitment::read(reader)?;
        let commitment_eq_proof = CommitmentEqProof::read(reader)?;

        Ok(Self::new(amount, commitment, commitment_eq_proof))
    }

    fn size(&self) -> usize {
        self.amount.size()
            + self.commitment.size()
            + self.commitment_eq_proof.size()
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

    #[test]
    fn test_invalid_balance_ownership_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let balance = 100u64;
        let amount = 10u64;
        let ct = keypair.get_public_key().encrypt(balance);

        // Create proof
        let mut transcript = Transcript::new(b"test");
        let proof = OwnershipProof::prove(&keypair, balance, amount, ct.clone(), &mut transcript).unwrap();

        // Verify the proof with a different balance ct
        let ct = keypair.get_public_key().encrypt(balance);
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();
        proof.pre_verify(keypair.get_public_key(), ct, &mut transcript, &mut batch_collector).unwrap();
        assert!(batch_collector.verify().is_err());
    }

    #[test]
    fn test_invalid_amount_ownership_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let balance = 0u64;
        let amount = 10u64;
        let ct = keypair.get_public_key().encrypt(balance);

        // Create proof
        let mut transcript = Transcript::new(b"test");
        assert!(OwnershipProof::prove(&keypair, balance, amount, ct, &mut transcript).is_err());
    }
}