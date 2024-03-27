use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
    traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
    ristretto::CompressedRistretto,
    RistrettoPoint, Scalar
};
use lazy_static::lazy_static;
use merlin::Transcript;
use rand::rngs::OsRng;
use thiserror::Error;
use std::iter;
use crate::{serializer::{Reader, ReaderError, Serializer, Writer}, transaction::MAX_TRANSFER_COUNT};

use super::{
    elgamal::{
        Ciphertext,
        DecompressionError,
        DecryptHandle,
        KeyPair,
        PedersenCommitment,
        PedersenOpening,
        PublicKey,
        G, H,
        RISTRETTO_COMPRESSED_SIZE,
        SCALAR_SIZE
    },
    ProtocolTranscript,
    TranscriptError
};
use zeroize::Zeroize;

// We are using 64 bits for the bulletproofs
pub const BULLET_PROOF_SIZE: usize = 64;

lazy_static! {
    // Bulletproof generators: party size is max transfers * 2 + 1
    // * 2 in case each transfer use a unique asset + 1 for xelis asset as fee and + 1 to be a power of 2
    pub static ref BP_GENS: BulletproofGens = BulletproofGens::new(BULLET_PROOF_SIZE, MAX_TRANSFER_COUNT * 2 + 2);
    pub static ref PC_GENS: PedersenGens = PedersenGens::default();
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ProofGenerationError {
    #[error("invalid format")]
    Decompression(#[from] DecompressionError),
    #[error("not enough funds in the account")]
    InsufficientFunds,
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
}

/// Proof that a commitment and ciphertext are equal.
#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CommitmentEqProof {
    Y_0: CompressedRistretto,
    Y_1: CompressedRistretto,
    Y_2: CompressedRistretto,
    z_s: Scalar,
    z_x: Scalar,
    z_r: Scalar,
}

#[derive(Error, Debug)]
#[error("batch multiscalar mul returned non identity point")]
pub struct MultiscalarMulVerificationError;

#[derive(Default)]
pub struct BatchCollector {
    dynamic_scalars: Vec<Scalar>,
    dynamic_points: Vec<RistrettoPoint>,
    g_scalar: Scalar,
    h_scalar: Scalar,
}

impl BatchCollector {
    pub fn verify(&self) -> Result<(), MultiscalarMulVerificationError> {
        let mega_check = RistrettoPoint::vartime_multiscalar_mul(
            self.dynamic_scalars
                .iter()
                .chain(iter::once(&self.g_scalar))
                .chain(iter::once(&self.h_scalar)),
            self.dynamic_points
                .iter()
                .cloned()
                .chain(iter::once(G))
                .chain(iter::once(*H)),
        );

        if mega_check.is_identity().into() {
            Ok(())
        } else {
            Err(MultiscalarMulVerificationError)
        }
    }
}

#[allow(non_snake_case)]
impl CommitmentEqProof {
    // warning: caller must make sure not to forget to hash the public key, ciphertext, commitment in the transcript as it is not done here
    pub fn new(
        source_keypair: &KeyPair,
        source_ciphertext: &Ciphertext,
        opening: &PedersenOpening,
        amount: u64,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.equality_proof_domain_separator();

        // extract the relevant scalar and Ristretto points from the inputs
        let P_source = source_keypair.get_public_key().as_point();
        let D_source = source_ciphertext.handle().as_point();

        let s = source_keypair.get_private_key().as_scalar();
        let x = Scalar::from(amount);
        let r = opening.as_scalar();

        // generate random masking factors that also serves as nonces
        let mut y_s = Scalar::random(&mut OsRng);
        let mut y_x = Scalar::random(&mut OsRng);
        let mut y_r = Scalar::random(&mut OsRng);

        let Y_0 = (&y_s * P_source).compress();
        let Y_1 =
            RistrettoPoint::multiscalar_mul(vec![&y_x, &y_s], vec![&(G), D_source]).compress();
        let Y_2 = RistrettoPoint::multiscalar_mul(vec![&y_x, &y_r], vec![&(G), &(*H)]).compress();

        // record masking factors in the transcript
        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);
        transcript.append_point(b"Y_2", &Y_2);

        let c = transcript.challenge_scalar(b"c");
        transcript.challenge_scalar(b"w");

        // compute the masked values
        let z_s = &(&c * s) + &y_s;
        let z_x = &(&c * &x) + &y_x;
        let z_r = &(&c * r) + &y_r;

        // zeroize random scalars
        y_s.zeroize();
        y_x.zeroize();
        y_r.zeroize();

        Self {
            Y_0,
            Y_1,
            Y_2,
            z_s,
            z_x,
            z_r,
        }
    }

    pub fn pre_verify(
        &self,
        source_pubkey: &PublicKey,
        source_ciphertext: &Ciphertext,
        destination_commitment: &PedersenCommitment,
        transcript: &mut Transcript,
        batch_collector: &mut BatchCollector,
    ) -> Result<(), ProofVerificationError> {
        transcript.equality_proof_domain_separator();

        // extract the relevant scalar and Ristretto points from the inputs
        let P_source = source_pubkey.as_point();
        let C_source = source_ciphertext.commitment().as_point();
        let D_source = source_ciphertext.handle().as_point();
        let C_destination = destination_commitment.as_point();

        // include Y_0, Y_1, Y_2 to transcript and extract challenges
        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;
        transcript.validate_and_append_point(b"Y_2", &self.Y_2)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.challenge_scalar(b"w"); // w used for batch verification
        let ww = &w * &w;

        let w_negated = -&w;
        let ww_negated = -&ww;

        // check that the required algebraic condition holds
        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(ProofVerificationError::CommitmentEqProof)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(ProofVerificationError::CommitmentEqProof)?;
        let Y_2 = self
            .Y_2
            .decompress()
            .ok_or(ProofVerificationError::CommitmentEqProof)?;

        let batch_factor = Scalar::random(&mut OsRng);

        // w * z_x * G + ww * z_x * G
        batch_collector.g_scalar += (w * self.z_x + ww * self.z_x) * batch_factor;
        // -c * H + ww * z_r * H
        batch_collector.h_scalar += (-c + ww * self.z_r) * batch_factor;

        batch_collector.dynamic_scalars.extend(
            [
                self.z_s,       // z_s
                -Scalar::ONE,   // -identity
                w * self.z_s,   // w * z_s
                w_negated * c,  // -w * c
                w_negated,      // -w
                ww_negated * c, // -ww * c
                ww_negated,     // -ww
            ]
            .map(|s| s * batch_factor),
        );
        batch_collector.dynamic_points.extend([
            P_source,      // P_source
            &Y_0,          // Y_0
            D_source,      // D_source
            C_source,      // C_source
            &Y_1,          // Y_1
            C_destination, // C_destination
            &Y_2,          // Y_2
        ]);

        Ok(())
    }
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CiphertextValidityProof {
    Y_0: CompressedRistretto,
    Y_1: CompressedRistretto,
    z_r: Scalar,
    z_x: Scalar,
}

#[allow(non_snake_case)]
impl CiphertextValidityProof {
    pub fn new(
        destination_pubkey: &PublicKey,
        amount: u64,
        opening: &PedersenOpening,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.ciphertext_validity_proof_domain_separator();

        let P_dest = destination_pubkey.as_point();

        let x = Scalar::from(amount);
        let r = opening.as_scalar();

        let mut y_r = Scalar::random(&mut OsRng);
        let mut y_x = Scalar::random(&mut OsRng);

        let Y_0 = RistrettoPoint::multiscalar_mul(vec![&y_r, &y_x], vec![&(*H), &G]).compress();
        let Y_1 = (&y_r * P_dest).compress();

        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);

        let c = transcript.challenge_scalar(b"c");
        transcript.challenge_scalar(b"w");

        // masked message and opening
        let z_r = &(&c * r) + &y_r;
        let z_x = &(&c * &x) + &y_x;

        y_r.zeroize();
        y_x.zeroize();

        Self { Y_0, Y_1, z_r, z_x }
    }

    pub fn pre_verify(
        &self,
        commitment: &PedersenCommitment,
        dest_pubkey: &PublicKey,
        dest_handle: &DecryptHandle,
        transcript: &mut Transcript,
        batch_collector: &mut BatchCollector,
    ) -> Result<(), ProofVerificationError> {
        transcript.ciphertext_validity_proof_domain_separator();

        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.challenge_scalar(b"w");

        let w_negated = -&w;

        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(ProofVerificationError::CiphertextValidityProof)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(ProofVerificationError::CiphertextValidityProof)?;

        let P_dest = dest_pubkey.as_point();

        let C = commitment.as_point();
        let D_dest = dest_handle.as_point();

        let batch_factor = Scalar::random(&mut OsRng);

        // z_x * G
        batch_collector.g_scalar += self.z_x * batch_factor;
        // z_r * H
        batch_collector.h_scalar += self.z_r * batch_factor;

        batch_collector.dynamic_scalars.extend(
            [
                -c,            // -c
                -Scalar::ONE,  // -identity
                w * self.z_r,  // w * z_r
                w_negated * c, // -w * c
                w_negated,     // -w
            ]
            .map(|s| s * batch_factor),
        );
        batch_collector.dynamic_points.extend([
            C,      // C
            &Y_0,   // Y_0
            P_dest, // P_dest
            D_dest, // D_dest
            &Y_1,   // Y_1
        ]);

        Ok(())
    }
}

#[allow(non_snake_case)]
impl Serializer for CommitmentEqProof {
    fn write(&self, writer: &mut Writer) {
        self.Y_0.write(writer);
        self.Y_1.write(writer);
        self.Y_2.write(writer);
        self.z_s.write(writer);
        self.z_x.write(writer);
        self.z_r.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let Y_0 = CompressedRistretto::read(reader)?;
        let Y_1 = CompressedRistretto::read(reader)?;
        let Y_2 = CompressedRistretto::read(reader)?;
        let z_s = Scalar::read(reader)?;
        let z_x = Scalar::read(reader)?;
        let z_r = Scalar::read(reader)?;

        Ok(Self { Y_0, Y_1, Y_2, z_s, z_x, z_r })
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE * 3 + SCALAR_SIZE * 3
    }    
}

#[allow(non_snake_case)]
impl Serializer for CiphertextValidityProof {
    fn write(&self, writer: &mut Writer) {
        self.Y_0.write(writer);
        self.Y_1.write(writer);
        self.z_r.write(writer);
        self.z_x.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let Y_0 = CompressedRistretto::read(reader)?;
        let Y_1 = CompressedRistretto::read(reader)?;
        let z_r = Scalar::read(reader)?;
        let z_x = Scalar::read(reader)?;

        Ok(Self { Y_0, Y_1, z_r, z_x })
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE * 2 + SCALAR_SIZE * 2
    }
}

#[allow(non_snake_case)]
impl Serializer for RangeProof {
    fn write(&self, writer: &mut Writer) {
        let bytes = self.to_bytes();
        writer.write_u16(bytes.len() as u16);
        writer.write_bytes(&bytes);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let len = reader.read_u16()? as usize;
        // 7 elements in Range Proof: 3 scalars and 4 points
        // 2 scalars in InnerProductProof
        // Each element is 32 bytes
        let min_size = 4 * RISTRETTO_COMPRESSED_SIZE + 5 * SCALAR_SIZE;
        if len % 32 != 0 || len < min_size {
            return Err(ReaderError::InvalidSize);
        }

        // Those are wrong points
        if (len - min_size) % 32 != 0 {
            return Err(ReaderError::InvalidSize);
        }

        // Maximum size of a RangeProof is 2 * MAX_TRANSFER_COUNT * RISTRETTO_COMPRESSED_SIZE
        let max_size_possible = min_size + (MAX_TRANSFER_COUNT * 2).next_power_of_two() * RISTRETTO_COMPRESSED_SIZE;
        if len > max_size_possible {
            return Err(ReaderError::InvalidSize);
        }

        let bytes = reader.read_bytes_ref(len)?;
        RangeProof::from_bytes(&bytes).map_err(|_| ReaderError::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_eq_proof() {
        let mut transcript = Transcript::new(b"test");
        let keypair = KeyPair::new();
        // Generate our initial balance
        let balance = 100u64;
        let source_balance = keypair.get_public_key().encrypt(balance);

        // Generate the ciphertext representing the TX amount
        let amount = 5;
        let opening = PedersenOpening::generate_new();
        let ciphertext = keypair.get_public_key().encrypt_with_opening(amount, &opening);

        // Commitment of the final balance using the same Opening
        let commitment = PedersenCommitment::new_with_opening(balance - amount, &opening);

        // Compute the final balance
        let final_balance = source_balance - ciphertext;

        // Generate the proof
        let proof = CommitmentEqProof::new(&keypair, &final_balance, &opening, balance - amount, &mut transcript);

        // Generate a new transcript
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();

        // Verify the proof
        let result = proof.pre_verify(
            keypair.get_public_key(),
            &final_balance,
            &commitment,
            &mut transcript,
            &mut batch_collector,
        );
        assert!(result.is_ok());
        assert!(batch_collector.verify().is_ok());
    }

    #[test]
    fn test_ciphertext_validity_proof() {
        let mut transcript = Transcript::new(b"test");
        let keypair = KeyPair::new();

        // Generate the commitment representing the transfer amount
        let amount = 5u64;
        let opening = PedersenOpening::generate_new();
        let commitment = PedersenCommitment::new_with_opening(amount, &opening);

        // Create the receiver handle
        let receiver_handle = keypair.get_public_key().decrypt_handle(&opening);

        // Generate the proof
        let proof = CiphertextValidityProof::new(keypair.get_public_key(), amount, &opening, &mut transcript);

        // Generate a new transcript
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();

        // Verify the proof
        let result = proof.pre_verify(
            &commitment,
            keypair.get_public_key(),
            &receiver_handle,
            &mut transcript,
            &mut batch_collector,
        );
        assert!(result.is_ok());
        assert!(batch_collector.verify().is_ok());
    }
}