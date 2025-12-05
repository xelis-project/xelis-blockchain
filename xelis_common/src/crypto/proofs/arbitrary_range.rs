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

/// Prove that a ciphertext is valid in 0..=M range.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArbitraryRangeProof {
    /// The maximum value we want to prove against.
    max_value: u64,
    /// The commitment of the delta between max value and the actual value.
    delta_commitment: CompressedCommitment,
    /// The commitment proof.
    /// Prove that `max_value - source_ct` encrypts the same value as `delta_commitment`.
    commitment_eq_proof: CommitmentEqProof,
    /// The range proof to prove `delta_commitment` is >= 0
    range_proof: RangeProof,
}

impl ArbitraryRangeProof {
    /// The opening used for the proof.
    /// This is a constant opening since we don't care about hiding the actual value of max_value.
    const OPENING: PedersenOpening = PedersenOpening::from_scalar(Scalar::ONE);

    /// Create a new arbitrary range proof.
    pub fn from(max_value: u64, delta_commitment: CompressedCommitment, commitment_eq_proof: CommitmentEqProof, range_proof: RangeProof) -> Self {
        Self { max_value, delta_commitment, commitment_eq_proof, range_proof }
    }

    /// Create a new arbitrary range proof with default transcript
    pub fn new(keypair: &KeyPair, value: u64, max_value: u64, ciphertext: Ciphertext) -> Result<Self, ProofGenerationError> {
        let mut transcript = Transcript::new(b"arbitrary_range_proof");
        Self::prove(keypair, value, max_value, ciphertext, &mut transcript)
    }

    /// Prove that the ciphertext encrypts a value less than or equal to max_value.
    pub fn prove(keypair: &KeyPair, value: u64, max_value: u64, ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<Self, ProofGenerationError> {
        if max_value == 0 || value > max_value {
            return Err(ProofGenerationError::Format);
        }

        // Delta between max_value and value
        let delta = max_value.checked_sub(value)
            .ok_or(ProofGenerationError::Format)?;

        // We don't want to reveal the whole transfer, we only want to prove that value <= max_value
        let opening = PedersenOpening::generate_new();
        let delta_commitment = PedersenCommitment::new_with_opening(delta, &opening)
            .compress();

        transcript.arbitrary_range_proof_domain_separator();
        transcript.append_u64(b"max_value", max_value);
        transcript.append_commitment(b"commitment", &delta_commitment);
        transcript.append_ciphertext(b"source_ct", &ciphertext.compress());
        transcript.append_public_key(b"public_key", &keypair.get_public_key().compress());

        // Compute the delta ciphertext
        // We subtract the original ciphertext from an encryption of max_value
        let ct = keypair.get_public_key().encrypt_with_opening(max_value, &Self::OPENING);
        let ct_delta = ct - ciphertext;

        // Generate the proof that the delta commitment is valid for the `max_value - ciphertext` ciphertext subtraction
        let commitment_eq_proof = CommitmentEqProof::new(keypair, &ct_delta, &opening, delta, TxVersion::V2, transcript);

        // Create a range proof to prove that whats left is >= 0
        let (range_proof, range_commitment) = RangeProof::prove_single(&BP_GENS, &PC_GENS, transcript, delta, &opening.as_scalar(), BULLET_PROOF_SIZE)?;
        assert_eq!(&range_commitment, delta_commitment.as_point());

        Ok(Self::from(max_value, delta_commitment, commitment_eq_proof, range_proof))
    }

    /// Get the maximum value of the proof.
    pub fn max_value(&self) -> u64 {
        self.max_value
    }

    pub fn delta_commitment(&self) -> &CompressedCommitment {
        &self.delta_commitment
    }

    pub fn commitment_eq_proof(&self) -> &CommitmentEqProof {
        &self.commitment_eq_proof
    }

    pub fn range_proof(&self) -> &RangeProof {
        &self.range_proof
    }

    /// Internal verify function to avoid code duplication.
    fn verify_internal(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<(PedersenCommitment, Ciphertext), ProofVerificationError> {
        if self.max_value == 0 {
            return Err(ProofVerificationError::Format);
        }

        transcript.arbitrary_range_proof_domain_separator();
        transcript.append_u64(b"max_value", self.max_value);
        transcript.validate_and_append_point(b"commitment", self.delta_commitment.as_point())?;
        transcript.append_ciphertext(b"source_ct", &source_ciphertext.compress());
        transcript.append_public_key(b"public_key", &public_key.compress());

        // Decompress the commitment
        let commitment = self.delta_commitment.decompress()?;

        // Compute the balance left
        let ct = public_key.encrypt_with_opening(self.max_value, &Self::OPENING);
        let ct_delta = ct - source_ciphertext;

        Ok((commitment, ct_delta))
    }

    /// Verify the Arbitrary Range proof using a batch collector.
    pub fn pre_verify(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript, batch_collector: &mut BatchCollector) -> Result<(), ProofVerificationError> {
        let (commitment, balance_left) = self.verify_internal(public_key, source_ciphertext, transcript)?;
        self.commitment_eq_proof.pre_verify(public_key, &balance_left, &commitment, TxVersion::V2, transcript, batch_collector)?;

        self.range_proof.verify_single(&BP_GENS, &PC_GENS, transcript, &(commitment.as_point().clone(), self.delta_commitment.as_point().clone()), BULLET_PROOF_SIZE)
            .map_err(ProofVerificationError::from)
    }

    /// Verify the Arbitrary Range proof.
    pub fn verify(&self, public_key: &PublicKey, source_ciphertext: Ciphertext, transcript: &mut Transcript) -> Result<(), ProofVerificationError> {
        let (commitment, balance_left) = self.verify_internal(public_key, source_ciphertext, transcript)?;
        self.commitment_eq_proof.verify(public_key, &balance_left, &commitment, transcript)?;

        self.range_proof.verify_single(&BP_GENS, &PC_GENS, transcript, &(commitment.as_point().clone(), self.delta_commitment.as_point().clone()), BULLET_PROOF_SIZE)
            .map_err(ProofVerificationError::from)
    }
}

impl Serializer for ArbitraryRangeProof {
    fn write(&self, writer: &mut Writer) {
        self.max_value.write(writer);
        self.delta_commitment.write(writer);
        self.commitment_eq_proof.write(writer);
        self.range_proof.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let max_value = u64::read(reader)?;
        let commitment = CompressedCommitment::read(reader)?;
        let commitment_eq_proof = CommitmentEqProof::read(reader)?;
        let range_proof = RangeProof::read(reader)?;

        Ok(Self::from(max_value, commitment, commitment_eq_proof, range_proof))
    }

    fn size(&self) -> usize {
        self.max_value.size()
            + self.delta_commitment.size()
            + self.commitment_eq_proof.size()
            + self.range_proof.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_arbitrary_range_proof_helper(value: u64, max_value: u64) {
        let keypair = KeyPair::new();
        // Generate the ciphertext
        let ct = keypair.get_public_key().encrypt(value);

        // Create proof
        let proof = ArbitraryRangeProof::new(&keypair, value, max_value, ct.clone()).unwrap();

        // Verify the proof
        assert!(
            proof.verify(keypair.get_public_key(), ct, &mut Transcript::new(b"arbitrary_range_proof"))
                .is_ok()
        );
    }

    #[test]
    fn test_arbitrary_range_proof() {
        // Test various values
        test_arbitrary_range_proof_helper(10, 100);
        test_arbitrary_range_proof_helper(0, 100);
        test_arbitrary_range_proof_helper(50, 100);
        test_arbitrary_range_proof_helper(99, 100);
        test_arbitrary_range_proof_helper(1, 1);
    }

    #[test]
    fn test_invalid_ct_arbitrary_range_proof() {
        let keypair = KeyPair::new();
        // Generate the ciphertext
        let value = 10u64;
        let max_value = 50u64;
        let ct = keypair.get_public_key().encrypt(value);

        // Create proof
        let proof = ArbitraryRangeProof::new(&keypair, value, max_value, ct.clone()).unwrap();

        // Verify the proof
        let inflated_ct = ct + Scalar::ONE;
        assert!(
            proof.verify(keypair.get_public_key(), inflated_ct, &mut Transcript::new(b"arbitrary_range_proof"))
                .is_err()
        );

        // Another CT
        let ct = keypair.get_public_key().encrypt(30u64);
        assert!(
            proof.verify(keypair.get_public_key(), ct, &mut Transcript::new(b"arbitrary_range_proof"))
                .is_err()
        );
    }
}