use bulletproofs::RangeProof;
use curve25519_dalek::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
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
    },
    transaction::TxVersion
};
use super::{
    BatchCollector,
    CommitmentEqProof,
    ProofGenerationError,
    ProofVerificationError,
    BP_GENS,
    PC_GENS,
    BULLET_PROOF_SIZE
};

/// Prove that the prover owns a certain amount (N > 0) of a given asset.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnershipProof {
    /// The amount of the asset.
    amount: u64,
    /// The commitment of the left balance.
    commitment: CompressedCommitment,
    /// The commitment proof.
    commitment_eq_proof: CommitmentEqProof,
    /// The range proof to prove that commitment is >= 0
    range_proof: RangeProof,
}

impl OwnershipProof {
    /// Create a new ownership proof.
    pub fn from(amount: u64, commitment: CompressedCommitment, commitment_eq_proof: CommitmentEqProof, range_proof: RangeProof) -> Self {
        Self { amount, commitment, commitment_eq_proof, range_proof }
    }

    /// Create a new ownership proof with default transcript
    pub fn new(keypair: &KeyPair, balance: u64, amount: u64, ciphertext: Ciphertext) -> Result<Self, ProofGenerationError> {
        let mut transcript = Transcript::new(b"ownership_proof");
        Self::prove(keypair, balance, amount, ciphertext, &mut transcript)
    }

    /// Prove the ownership of the asset.
    pub fn prove(keypair: &KeyPair, balance: u64, amount: u64, ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<Self, ProofGenerationError> {
        if amount == 0 {
            return Err(ProofGenerationError::Format);
        }

        let left = balance.checked_sub(amount)
            .ok_or(ProofGenerationError::InsufficientFunds {
                required: amount,
                available: balance
            })?;

        // We don't want to reveal the whole balance, so we create a new Commitment with a random opening.
        let opening = PedersenOpening::generate_new();
        let left_commitment = PedersenCommitment::new_with_opening(left, &opening)
            .compress();

        transcript.ownership_proof_domain_separator();
        transcript.append_u64(b"amount", amount);
        transcript.append_commitment(b"commitment", &left_commitment);
        transcript.append_ciphertext(b"source_ct", &ciphertext.compress());
        transcript.append_public_key(b"public_key", &keypair.get_public_key().compress());

        // Compute the balance left
        let ct_left = ciphertext - Scalar::from(amount);

        // Generate the proof that the final balance is ? minus N after applying the commitment.
        let commitment_eq_proof = CommitmentEqProof::new(keypair, &ct_left, &opening, left, TxVersion::V2, transcript);

        // Create a range proof to prove that whats left is >= 0
        let (range_proof, range_commitment) = RangeProof::prove_single(&BP_GENS, &PC_GENS, transcript, left, &opening.as_scalar(), BULLET_PROOF_SIZE)?;
        assert_eq!(&range_commitment, left_commitment.as_point());

        Ok(Self::from(amount, left_commitment, commitment_eq_proof, range_proof))
    }

    /// Get the amount being proven.
    #[inline]
    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    pub fn commitment_eq_proof(&self) -> &CommitmentEqProof {
        &self.commitment_eq_proof
    }

    pub fn range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    /// Internal verify function to avoid code duplication.
    fn verify_internal(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<(PedersenCommitment, Ciphertext), ProofVerificationError> {
        if self.amount == 0 {
            return Err(ProofVerificationError::Format);
        }

        transcript.ownership_proof_domain_separator();
        transcript.append_u64(b"amount", self.amount);
        transcript.validate_and_append_point(b"commitment", self.commitment.as_point())?;
        transcript.append_ciphertext(b"source_ct", &source_ciphertext.compress());
        transcript.append_public_key(b"public_key", &public_key.compress());

        // Decompress the commitment
        let commitment = self.commitment.decompress()?;

        // Compute the balance left
        let balance_left = source_ciphertext - Scalar::from(self.amount);

        Ok((commitment, balance_left))
    }

    /// Verify the ownership proof using a batch collector.
    pub fn pre_verify(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript, batch_collector: &mut BatchCollector) -> Result<(), ProofVerificationError> {
        let (commitment, balance_left) = self.verify_internal(public_key, source_ciphertext, transcript)?;
        self.commitment_eq_proof.pre_verify(public_key, &balance_left, &commitment, TxVersion::V2, transcript, batch_collector)?;

        self.range_proof.verify_single(&BP_GENS, &PC_GENS, transcript, &(commitment.as_point().clone(), self.commitment.as_point().clone()), BULLET_PROOF_SIZE)
            .map_err(ProofVerificationError::from)
    }

    /// Verify the ownership proof.
    pub fn verify(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<(), ProofVerificationError> {
        let (commitment, balance_left) = self.verify_internal(public_key, source_ciphertext, transcript)?;
        self.commitment_eq_proof.verify(public_key, &balance_left, &commitment, transcript)?;

        self.range_proof.verify_single(&BP_GENS, &PC_GENS, transcript, &(commitment.as_point().clone(), self.commitment.as_point().clone()), BULLET_PROOF_SIZE)
            .map_err(ProofVerificationError::from)
    }
}

impl Serializer for OwnershipProof {
    fn write(&self, writer: &mut Writer) {
        self.amount.write(writer);
        self.commitment.write(writer);
        self.commitment_eq_proof.write(writer);
        self.range_proof.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let amount = u64::read(reader)?;
        let commitment = CompressedCommitment::read(reader)?;
        let commitment_eq_proof = CommitmentEqProof::read(reader)?;
        let range_proof = RangeProof::read(reader)?;

        Ok(Self::from(amount, commitment, commitment_eq_proof, range_proof))
    }

    fn size(&self) -> usize {
        self.amount.size()
            + self.commitment.size()
            + self.commitment_eq_proof.size()
            + self.range_proof.size()
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
        let proof = OwnershipProof::new(&keypair, balance, amount, ct.clone()).unwrap();

        // Verify the proof
        assert!(proof.verify(keypair.get_public_key(), ct, &mut Transcript::new(b"ownership_proof")).is_ok());
    }

    #[test]
    fn test_invalid_balance_ownership_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let balance = 100u64;
        let amount = 10u64;
        let ct = keypair.get_public_key().encrypt(balance);

        // Create proof
        let proof = OwnershipProof::new(&keypair, balance, amount, ct.clone()).unwrap();

        // Verify the proof with a different balance ct
        let ct = keypair.get_public_key().encrypt(balance);
        assert!(proof.verify(keypair.get_public_key(), ct, &mut Transcript::new(b"ownership_proof")).is_err());
    }

    #[test]
    fn test_invalid_amount_ownership_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let balance = 0u64;
        let amount = 10u64;
        let ct = keypair.get_public_key().encrypt(balance);

        // Create proof
        assert!(OwnershipProof::new(&keypair, balance, amount, ct).is_err());
    }

    #[test]
    fn test_inflated_balance_ownership_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let balance = 100u64;
        let amount = 10u64;
        let ct = keypair.get_public_key().encrypt(balance);

        // Create proof
        let mut proof = OwnershipProof::new(&keypair, balance, amount, ct.clone()).unwrap();
        let inflate = 100;

        proof.amount += inflate;
        let mut decompressed = proof.commitment.decompress().unwrap();
        decompressed -= Scalar::from((-(inflate as i64)) as u64);

        proof.commitment = decompressed.compress();

        assert!(proof.verify(keypair.get_public_key(), ct, &mut Transcript::new(b"ownership_proof")).is_err());
    }

    #[test]
    fn test_fake_commitment_ownership_proof() {
        let keypair = KeyPair::new();
        // Generate the balance
        let balance = 10u64;

        // How much we want to prove as ownership
        let amount = 10u64;
        // By how much we want to inflate it
        let inflate = 10u64;

        // Current balance on chain
        let balance_ct = keypair.get_public_key().encrypt(balance);

        let left = balance.checked_sub(amount).unwrap();

        let mut transcript = Transcript::new(b"ownership_proof");
        // We don't want to reveal the whole balance, so we create a new Commitment with a random opening.
        let opening = PedersenOpening::generate_new();
        let mut left_commitment = PedersenCommitment::new_with_opening(left, &opening);
        left_commitment -= Scalar::from(inflate);

        let left_commitment = left_commitment.compress();

        transcript.ownership_proof_domain_separator();
        transcript.append_u64(b"amount", amount + inflate);
        transcript.append_commitment(b"commitment", &left_commitment);
        transcript.append_ciphertext(b"source_ct", &balance_ct.compress());

        // Compute the balance left
        let ct_left = balance_ct.clone() - Scalar::from(amount + inflate);

        // expected left balance + the inflated amount
        let left_scalar = Scalar::from(left) - Scalar::from(inflate);

        let commitment_eq_proof = CommitmentEqProof::new(&keypair, &ct_left, &opening, left_scalar, TxVersion::V2, &mut transcript);

        // Range proof prevent such exploit by making sure our balance left commitment is >= 0
        let (range_proof, _) = RangeProof::prove_single(&BP_GENS, &PC_GENS, &mut transcript, left, &opening.as_scalar(), BULLET_PROOF_SIZE).unwrap();

        // Create proof
        let proof = OwnershipProof {
            commitment: left_commitment,
            amount: amount + inflate,
            commitment_eq_proof,
            range_proof
        };

        assert!(proof.verify(keypair.get_public_key(), balance_ct, &mut Transcript::new(b"ownership_proof")).is_err());
    }
}