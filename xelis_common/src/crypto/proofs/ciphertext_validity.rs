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
    },
    transaction::TxVersion
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
    Y_2: Option<CompressedRistretto>,
    z_r: Scalar,
    z_x: Scalar,
}

#[allow(non_snake_case)]
impl CiphertextValidityProof {
    pub fn new(
        destination_pubkey: &PublicKey,
        source_pubkey: Option<&PublicKey>,
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

        let Y_2 = source_pubkey.map(|P_source| (&y_r * P_source.as_point()).compress());

        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);
        if let Some(Y_2) = Y_2.as_ref() {
            transcript.append_point(b"Y_2", Y_2);
        }

        let c = transcript.challenge_scalar(b"c");
        transcript.challenge_scalar(b"w");

        // masked message and opening
        let z_r = &(&c * r) + &y_r;
        let z_x = &(&c * &x) + &y_x;

        y_r.zeroize();
        y_x.zeroize();

        Self { Y_0, Y_1, Y_2, z_r, z_x }
    }

    pub fn pre_verify(
        &self,
        commitment: &PedersenCommitment,
        dest_pubkey: &PublicKey,
        sender_pubkey: &PublicKey,
        dest_handle: &DecryptHandle,
        sender_handle: &DecryptHandle,
        check_y_2: bool,
        transcript: &mut Transcript,
        batch_collector: &mut BatchCollector,
    ) -> Result<(), ProofVerificationError> {
        transcript.ciphertext_validity_proof_domain_separator();

        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;
        if let Some(Y_2) = self.Y_2.as_ref().filter(|_| check_y_2) {
            transcript.validate_and_append_point(b"Y_2", Y_2)?;
        }

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
        let Y_2 = if let Some(Y_2) = self.Y_2.as_ref() {
            Some(
                Y_2
                    .decompress()
                    .ok_or(ProofVerificationError::CiphertextValidityProof)?,
            )
        } else {
            None
        };

        if Y_2.is_some() != check_y_2 {
            return Err(ProofVerificationError::CiphertextValidityProof);
        }

        let P_dest = dest_pubkey.as_point();
        let P_source = sender_pubkey.as_point();

        let C = commitment.as_point();
        let D_dest = dest_handle.as_point();
        let D_source = sender_handle.as_point();

        let batch_factor = Scalar::random(&mut OsRng);

        // z_x * G
        batch_collector.g_scalar += self.z_x * batch_factor;
        // z_r * H
        batch_collector.h_scalar += self.z_r * batch_factor;

        let w_z_r = w * self.z_r;
        let w_negated_c = w_negated * c;
        batch_collector.dynamic_scalars.extend(
            [
                -c,            // -c
                -Scalar::ONE,  // -identity
                w_z_r,  // w * z_r
                w_negated_c, // -w * c
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

        if let Some(Y_2) = Y_2 {
            batch_collector.dynamic_scalars.extend([
                w * w_z_r,           // w * z_r
                w * w_negated_c, // -w * c
                w * w_negated,   // -w
            ]);

            batch_collector.dynamic_points.extend([
                P_source, // P_source
                D_source, // D_source
                &Y_2,     // Y_2
            ]);
        }

        Ok(())
    }
}

#[allow(non_snake_case)]
impl Serializer for CiphertextValidityProof {
    fn write(&self, writer: &mut Writer) {
        self.Y_0.write(writer);
        self.Y_1.write(writer);
        if let Some(Y_2) = self.Y_2 {
            Y_2.write(writer);
        }
        self.z_r.write(writer);
        self.z_x.write(writer);
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let version: TxVersion = reader.context()
            .get_copy()?;
        let Y_0 = CompressedRistretto::read(reader)?;
        let Y_1 = CompressedRistretto::read(reader)?;
        let Y_2 = if version >= TxVersion::V1 {
            Some(CompressedRistretto::read(reader)?)
        } else {
            None
        };

        let z_r = Scalar::read(reader)?;
        let z_x = Scalar::read(reader)?;

        Ok(Self { Y_0, Y_1, Y_2, z_r, z_x })
    }

    fn size(&self) -> usize {
        RISTRETTO_COMPRESSED_SIZE * 2 + SCALAR_SIZE * 2 + self.Y_2.map_or(0, |_| RISTRETTO_COMPRESSED_SIZE)
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
        let sender = KeyPair::new();

        // Generate the commitment representing the transfer amount
        let amount = 5u64;
        let opening = PedersenOpening::generate_new();
        let commitment = PedersenCommitment::new_with_opening(amount, &opening);

        // Create the receiver handle
        let receiver_handle = keypair.get_public_key().decrypt_handle(&opening);
        // Create the sender handle
        let sender_handle = sender.get_public_key().decrypt_handle(&opening);

        // Generate the proof
        let proof = CiphertextValidityProof::new(keypair.get_public_key(), Some(sender.get_public_key()), amount, &opening, &mut transcript);

        // Generate a new transcript
        let mut transcript = Transcript::new(b"test");
        let mut batch_collector = BatchCollector::default();

        // Verify the proof
        let result = proof.pre_verify(
            &commitment,
            keypair.get_public_key(),
            sender.get_public_key(),
            &receiver_handle,
            &sender_handle,
            true,
            &mut transcript,
            &mut batch_collector,
        );
        assert!(result.is_ok());
        assert!(batch_collector.verify().is_ok());
    }
}