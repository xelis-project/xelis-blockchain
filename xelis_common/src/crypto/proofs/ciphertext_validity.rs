use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use merlin::Transcript;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::{
    crypto::{
        elgamal::{
            DecryptHandle,
            PedersenCommitment,
            PedersenOpening,
            PublicKey,
            RISTRETTO_COMPRESSED_SIZE,
            SCALAR_SIZE
        },
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
    ProofVerificationError,
    PC_GENS
};

/// Cipher text validity proof.
/// This proof is used to prove that a given ciphertext is valid and was created correctly for the right recipient.
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

        let Y_0 = PC_GENS.commit(y_x, y_r).compress();
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

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;
    use super::*;

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